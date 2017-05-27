use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../lib";
use Data::Section::Simple qw(get_data_section);
use MyCrypt;
use Mustache::Tiny;
use Plack::Request;
use Plack::Session;
use Plack::Builder;

my $users = {
    'alice' => {
        'account' => 'alice',
        # otpauth://totp/Example:alice@example.net?secret=PBHWM6TSGJMEGZRU
        'totpkey' => 'xOfzr2XCf4',
        'password' => MyCrypt->xcrypt('7nDgOqcl4Loz160g', 'P7detwry$'),
    },
};
my $templates = get_data_section;

sub app_default {
    my($env) = @_;
    my $req = Plack::Request->new($env);
    my $session = Plack::Session->new($env);
    my $path = $req->path_info;
    my($owner) = $path =~ m{\A/([A-Za-z0-9\-_.~]+)}msx;
    my $account = $session->get('user.account');
    my $tmpl = $path eq q(/) ? 'index.html' : 'home.html';
    return render($req, 200, $tmpl, {
        'owner' => $owner || q(),
        'account' => $account,
        'home' => $session->get('user.redirect_uri') || q(),
        'login' => '/login',
        'logout' => '/logout',
    })->finalize;
}

sub auth_totp {
    my($account, $password, $env) = @_;
    exists $users->{$account}{'totpkey'} or return;
    my $key = $users->{$account}{'totpkey'};
    $password eq MyCrypt->totp_sha1_6(time, $key) or return;
    return {'account' => $account, 'redirect_uri' => "/$account"};
}

sub auth_xcrypt {
    my($account, $password, $env) = @_;
    exists $users->{$account}{'password'} or return;
    my $saltyhash = $users->{$account}{'password'};
    $saltyhash eq MyCrypt->xcrypt($password, $saltyhash) or return;
    return {'account' => $account, 'redirect_uri' => "/$account"};
}

sub auth_render {
    my($req, $param) = @_;
    return render($req, 200, 'login.html', $param);
}

sub render {
    my($req, $code, $name, $param) = @_;
    $param ||= {};
    my $body = Mustache::Tiny->subst($templates->{$name}, $param);
    my $res = $req->new_response($code);
    $res->content_type('text/html; charset=UTF-8');
    $res->content_length(length $body);
    $res->body($body);
    return $res;
}

builder {
    enable 'Session';
    enable 'Auth::LoginChain',
        login_spec => [
            {'uri' => '/login',
             'authenticator' => \&auth_totp,
             'renderer' => \&auth_render,
             'realm' => 'One-Time Password'},
            {'uri' => '/login2',
             'authenticator' => \&auth_xcrypt,
             'renderer' => \&auth_render,
             'realm' => 'Password'},
        ],
        logout_spec => {
            'uri' => '/logout',
            'redirect_uri' => '/'
        };
    \&app_default;
};

__DATA__

@@ index.html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<title>index</title>
</head>
<body>
<h1>index</h1>
<p>Top |
{{#account}}<a href="{{home}}">{{account}} Home</a>
| <a href="{{logout}}">Logout</a>{{/account}}
{{^account}}<a href="{{login}}">Login</a>{{/account}}</p>
</body>
</html>

@@ home.html
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8" />
<title>{{owner}} Home</title>
</head>
<body>
<h1>{{owner}} Home</h1>
<p><a href="/">Top</a> |
{{#account}}{{account}} Home | <a href="{{logout}}">Logout</a>{{/account}}
{{^account}}<a href="{{login}}">Login</a>{{/account}}</p>
</body>
</html>

@@ login.html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<title>{{#realm}}{{realm}} - {{/realm}}Authenticate</title>
</head>
<body>
<h1>{{#realm}}{{realm}} - {{/realm}}Authenticate</h1>

<p><a href="/">Top</a>
{{#account}}
| already logged-in <a href="{{home}}">{{account}} Home</a>
{{/account}}</p>

<form method="post">
<fieldset class="main_fieldset">
<table>
<tr>
<td><label class="label" for="account">Username: </label></td>
<td><input type="text" name="account" value="{{faccount}}" /></td>
</tr>
<tr>
<td><label class="label" for="password">{{#realm}}{{realm}}{{/realm}}
{{^realm}}Password{{/realm}}: </label></td>
<td><input type="password" name="password" /><input type="hidden" name="protect" value="{{fprotect}}" /></td>
</tr>
<tr>
<td>&nbsp;</td>
<td><input type="submit" value="{{^account}}Login{{/account}}
{{#account}}Validate{{/account}}" /></td>
</tr>
</table>
</fieldset>
</form>
</body>
</html>

