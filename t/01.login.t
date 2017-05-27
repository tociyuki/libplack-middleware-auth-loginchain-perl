use strict;
use warnings;
use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;

my $users = {
    'alice' => {
        'account' => 'alice',
        'password1' => 'pAsSWoRd1',
        'password2' => 'PaSsWorD2',
    },
};

sub auth_one {
    my($account, $password, $env) = @_;
    exists $users->{$account}{'password1'} or return;
    $password eq $users->{$account}{'password1'} or return;
    return {'account' => $account, 'redirect_uri' => "/$account"};
}

sub auth_two {
    my($account, $password, $env) = @_;
    exists $users->{$account}{'password2'} or return;
    $password eq $users->{$account}{'password2'} or return;
    return {'account' => $account, 'redirect_uri' => "/$account"};
}

sub auth_renderer {
    my($req, $param) = @_;
    my $t = "title\tlogin\n";
    for my $k (qw(realm account home faccount fprotect)) {
        $t .= $k . "\t" . $param->{$k} . "\n";
    }
    my $res = $req->new_response(200);
    $res->content_type('text/plain');
    $res->body($t);
    return $res;
}

my $app = sub {
    my($env) = @_;
    my $account = exists $env->{'psgix.session'}{'user.account'}
        ? $env->{'psgix.session'}{'user.account'} : 'GUEST';
    return [200, ['Content-Type' => 'text/plain'], ["Hello $account"]];
};
$app = builder {
    enable 'Session';
    enable 'Auth::LoginChain',
        login_spec => [
            {'uri' => '/login',
             'authenticator' => \&auth_one,
             'renderer' => \&auth_renderer,
             'realm' => 'First Password'},
            {'uri' => '/login2',
             'authenticator' => \&auth_two,
             'renderer' => \&auth_renderer,
             'realm' => 'Second Password'},
        ],
        logout_spec => {
            'uri' => '/logout',
            'redirect_uri' => '/'
        };
    $app;
};

my $test = Plack::Test->create($app);
my($cookie, $account, $protect);

{
    my $res = $test->request(GET "/");
    is $res->content, "Hello GUEST", "get /";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

#diag "GET /login => POST /login => GET /login2 => POST /login2 => GET /alice";

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, '', 'get /login account';
    is $param{'home'}, '', 'get /login home';
    is $param{'faccount'}, '', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login2', "post /login alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login2",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login2 title';
    is $param{'realm'}, 'Second Password', 'get /login2 realm';
    is $param{'account'}, '', 'get /login2 account';
    is $param{'home'}, '', 'get /login2 home';
    is $param{'faccount'}, 'alice', 'get /login2 faccount';
    ok $param{'fprotect'}, 'get /login2 fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login2", [
        'account' => 'alice',
        'password' => 'PaSsWorD2',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login2 alice code";
    is $res->headers->header('Location'), '/alice', "post /login2 alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/alice",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get /alice";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /alice set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

#diag "GET /login => POST /login => GET /login2 => POST /login2 => GET /alice";

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, 'alice', 'get /login account';
    is $param{'home'}, '/alice', 'get /login home';
    is $param{'faccount'}, 'alice', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login2', "post /login alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login2",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login2 title';
    is $param{'realm'}, 'Second Password', 'get /login2 realm';
    is $param{'account'}, 'alice', 'get /login2 account';
    is $param{'home'}, '/alice', 'get /login2 home';
    is $param{'faccount'}, 'alice', 'get /login2 faccount';
    ok $param{'fprotect'}, 'get /login2 fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login2", [
        'account' => 'alice',
        'password' => 'PaSsWorD2',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login2 alice code";
    is $res->headers->header('Location'), '/alice', "post /login2 alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/alice",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get /alice";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /alice set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

#diag "GET /login => GET / => GET /login2 => GET /";

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, 'alice', 'get /login account';
    is $param{'home'}, '/alice', 'get /login home';
    is $param{'faccount'}, 'alice', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login2",
        'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "get /login2 alice code";
    is $res->headers->header('Location'), '/login', "get /login2 alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

#diag "GET /login => POST /login => GET /login2 => GET / => GET /login2";

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, 'alice', 'get /login account';
    is $param{'home'}, '/alice', 'get /login home';
    is $param{'faccount'}, 'alice', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login2', "post /login alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login2",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login2 title';
    is $param{'realm'}, 'Second Password', 'get /login2 realm';
    is $param{'account'}, 'alice', 'get /login2 account';
    is $param{'home'}, '/alice', 'get /login2 home';
    is $param{'faccount'}, 'alice', 'get /login2 faccount';
    ok $param{'fprotect'}, 'get /login2 fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login2",
        'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "get /login2 alice code";
    is $res->headers->header('Location'), '/login', "get /login2 alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, 'alice', 'get /login account';
    is $param{'home'}, '/alice', 'get /login home';
    is $param{'faccount'}, 'alice', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(GET "/alice",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get /alice";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /alice set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/logout",
        'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "get /logout code";
    is $res->headers->header('Location'), '/', "get /logout location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /logout set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello GUEST", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, '', 'get /login account';
    is $param{'home'}, '', 'get /login home';
    is $param{'faccount'}, '', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login2', "post /login alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login2",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login2 title';
    is $param{'realm'}, 'Second Password', 'get /login2 realm';
    is $param{'account'}, '', 'get /login2 account';
    is $param{'home'}, '', 'get /login2 home';
    is $param{'faccount'}, 'alice', 'get /login2 faccount';
    ok $param{'fprotect'}, 'get /login2 fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login2", [
        'account' => 'alice',
        'password' => 'PaSsWorD2',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login2 alice code";
    is $res->headers->header('Location'), '/alice', "post /login2 alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/alice",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get /alice";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /alice set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/logout",
        'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "get /logout code";
    is $res->headers->header('Location'), '/', "get /logout location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /logout set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello GUEST", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, '', 'get /login account';
    is $param{'home'}, '', 'get /login home';
    is $param{'faccount'}, '', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'INVALID',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login', "post /login alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login', "post /login alice location protect error";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, '', 'get /login account';
    is $param{'home'}, '', 'get /login home';
    is $param{'faccount'}, '', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login2", [
        'account' => 'alice',
        'password' => 'PaSsWorD2',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login', "post /login alice location phase error";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, '', 'get /login account';
    is $param{'home'}, '', 'get /login home';
    is $param{'faccount'}, '', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login2', "post /login alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login2",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login2 title';
    is $param{'realm'}, 'Second Password', 'get /login2 realm';
    is $param{'account'}, '', 'get /login2 account';
    is $param{'home'}, '', 'get /login2 home';
    is $param{'faccount'}, 'alice', 'get /login2 faccount';
    ok $param{'fprotect'}, 'get /login2 fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login', "post /login alice location phase error";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, '', 'get /login account';
    is $param{'home'}, '', 'get /login home';
    is $param{'faccount'}, '', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login2', "post /login alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(POST "/login2", [
        'account' => 'alice',
        'password' => 'PaSsWorD2',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login2 alice code";
    is $res->headers->header('Location'), '/login', "post /login2 alice location phase error";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello GUEST", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login', "post /login alice location protect error";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(POST "/login2", [
        'account' => 'alice',
        'password' => 'PaSsWorD2',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login2 alice code";
    is $res->headers->header('Location'), '/login', "post /login2 alice location protect error";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login title';
    is $param{'realm'}, 'First Password', 'get /login realm';
    is $param{'account'}, '', 'get /login account';
    is $param{'home'}, '', 'get /login home';
    is $param{'faccount'}, '', 'get /login faccount';
    ok $param{'fprotect'}, 'get /login fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login", [
        'account' => 'alice',
        'password' => 'pAsSWoRd1',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login alice code";
    is $res->headers->header('Location'), '/login2', "post /login alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/login2",
        'Cookie' => "plack_session=$cookie");
    my %param = map { chomp; split /\t/, $_, 2 } split /\n/, $res->content;
    is $param{'title'}, 'login', 'get /login2 title';
    is $param{'realm'}, 'Second Password', 'get /login2 realm';
    is $param{'account'}, '', 'get /login2 account';
    is $param{'home'}, '', 'get /login2 home';
    is $param{'faccount'}, 'alice', 'get /login2 faccount';
    ok $param{'fprotect'}, 'get /login2 fprotect';
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
    $account = $param{'faccount'};
    $protect = $param{'fprotect'};
}

{
    my $res = $test->request(POST "/login2", [
        'account' => 'alice',
        'password' => 'PaSsWorD2',
        'protect' => $protect
    ], 'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "post /login2 alice code";
    is $res->headers->header('Location'), '/alice', "post /login2 alice location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'post /login2 set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/alice",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello alice", "get /alice";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /alice set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/logout",
        'Cookie' => "plack_session=$cookie");
    is $res->code, 303, "get /logout code";
    is $res->headers->header('Location'), '/', "get /logout location";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get /logout set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

{
    my $res = $test->request(GET "/",
        'Cookie' => "plack_session=$cookie");
    is $res->content, "Hello GUEST", "get / content";
    my $set_cookie = $res->headers->header('Set-Cookie') || q();
    like $set_cookie, qr/\bplack_session=\S/msx, 'get / set-cookie';
    ($cookie) = $set_cookie =~ m/\bplack_session=([0-9a-f]+)/msx;
}

done_testing;
