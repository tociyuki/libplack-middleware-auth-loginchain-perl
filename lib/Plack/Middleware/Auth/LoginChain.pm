package Plack::Middleware::Auth::LoginChain;
use strict;
use warnings;
use MIME::Base64 qw(encode_base64url);
use Crypt::OpenSSL::Random qw(random_bytes);
use Carp ();
use Plack::Request;
use Plack::Session;
use Plack::Util;
use parent qw(Plack::Middleware);

our $VERSION = '0.02';

use Plack::Util::Accessor qw(login_spec logout_spec);

sub prepare_app {
    my($self) = @_;
    my $login_spec = $self->login_spec
        or Carp::croak "LoginChain: lost login_spec\n";
    'ARRAY' eq ref $login_spec
        or Carp::croak "LoginChain:login_spec must be ARRAYREF\n";
    @{$login_spec} > 0
        or Carp::croak "LoginChain:login_spec must have at least 1 element\n";
    for my $w (@{$login_spec}) {
        'HASH' eq ref $w
            or Carp::croak "LoginChain: login_spec->[i] must be HASHREF\n";
        $w->{'uri'}
            or Carp::croak "LoginChain: lost login_spec->[i]{uri}\n";
        my $authenticator = $w->{'authenticator'};
        'CODE' eq ref $authenticator
            or Carp::croak "LoginChain: lost login_spec->[i]{authenticator}\n";
        my $responder = $w->{'responder'};
        'CODE' eq ref $responder
            or Carp::croak "LoginChain: lost login_spec->[i]{responder}\n";
    }
    my $logout_spec = $self->logout_spec
        or Carp::croak "LoginChain: lost logout_spec\n";
    'HASH' eq ref $logout_spec
        or Carp::croak "LoginChain: logout_spec must be HASHREF\n";
}

sub gen_protect {
    my($self) = @_;
    return encode_base64url(random_bytes(12));
}

sub check_protect {
    my($self, $param) = @_;
    $param->{'uri.protect'} or return;
    $param->{'post.protect'} or return;
    return $param->{'uri.protect'} eq $param->{'post.protect'};    
}

sub authenticate {
    my($self, $idx, $req, $param) = @_;
    my $uri = $self->login_spec->[$idx]{'uri'};
    my $first_uri = $self->login_spec->[0]{'uri'};
    my $account = $param->{'post.account'} or return;
    my $password = $param->{'post.password'} or return;
    $uri eq $first_uri or $param->{'uri.account'} eq $account or return;
    not $param->{'account'} or $param->{'account'} eq $account or return;

    my $authenticator = $self->login_spec->[$idx]{'authenticator'};
    my $auth = $authenticator->($account, $password, $req->env) or return;

    if (! ref $auth) {
        $auth = {'account' => $account};
    }
    $auth->{'redirect_uri'} ||= q(/);
    return $auth;
}

sub update_session {
    my($self, $idx, $env, $auth) = @_;
    my $session = Plack::Session->new($env);
    if (! $auth) {
        $session->remove('account');
        $session->remove('redirect_uri');
    }
    elsif ($idx >= $#{$self->login_spec}) {
        $session->set('account', $auth->{'account'});
        $session->set('redirect_uri', $auth->{'redirect_uri'});
    }
    else {
        $self->clean_session($env);
        my $chain_uri = $self->login_spec->[$idx + 1]{'uri'};
        $session->set($chain_uri . '#account', $auth->{'account'});
    }
    return $self;
}

sub clean_session {
    my($self, $env) = @_;
    my $session = Plack::Session->new($env);
    for my $stage (@{$self->login_spec}) {
        $session->remove($stage->{'uri'} . '#account');
        $session->remove($stage->{'uri'} . '#protect');
    }
    $env->{'.loginchain.erase'} = Plack::Util::FALSE;
    return $self;
}

sub call {
    my($self, $env) = @_;
    $env->{'psgix.session.options'}{'change_id'} = 1;
    local $env->{'.loginchain.erase'} = Plack::Util::TRUE;
    my $res = $self->dispatch($env);
    if ($env->{'.loginchain.erase'}) {
        $self->clean_session($env);
    }
    return $res;
}

sub dispatch {
    my($self, $env) = @_;
    my $method = $env->{'REQUEST_METHOD'};
    $method = 'HEAD' eq $method ? 'GET' : $method;
    for my $idx (0 .. $#{$self->login_spec}) {
        my $opt = $self->login_spec->[$idx];
        if ($opt->{'uri'} eq $env->{'PATH_INFO'}) {
            'GET'  eq $method and return $self->get_login($idx, $env);
            'POST' eq $method and return $self->post_login($idx, $env);
            return $self->method_not_allowed($env);
        }
    }
    if ($self->logout_spec->{'uri'} eq $env->{'PATH_INFO'}) {
        'GET'  eq $method and return $self->call_logout($env);
        'POST' eq $method and return $self->call_logout($env);
        return $self->method_not_allowed($env);
    }
    $self->clean_session($env);
    return $self->app->($env);
}

sub get_login {
    my($self, $idx, $env) = @_;
    my $session = Plack::Session->new($env);
    my $req = Plack::Request->new($env);
    my $opt = $self->login_spec->[$idx];
    my $uri = $opt->{'uri'};
    my $first_uri = $self->login_spec->[0]{'uri'};
    my $account = $session->get('account') || q();
    my $uri_account = $session->get($uri . '#account') || q();
    if ($uri ne $first_uri && ! $uri_account) {
        return $self->redirect_first_phase($req);
    }
    my $uri_protect = $self->gen_protect;
    $self->clean_session($env);
    $session->set($uri . '#account', $uri_account);
    $session->set($uri . '#protect', $uri_protect);
    my $res = $opt->{'responder'}->($req, {
        'realm' => $opt->{'realm'} || q(),
        'norealm' => ($opt->{'realm'} ? q() : 1),
        'account' => $account,
        'noaccount' => ($account ? q() : 1),
        'home' => $session->get('redirect_uri') || q(),
        'faccount' => ($uri eq $first_uri ? $account : $uri_account),
        'fprotect' => $uri_protect,
    });
    $res->headers->header('Content-Security-Policy' => q(default-src 'self'));
    $res->headers->header('X-Content-Type-Options' => q("nosniff"));
    $res->headers->header('X-XSS-Protection' => q(1;mode=block));
    $res->headers->header('X-Frame-Options' => q(DENY));
    return $res->finalize;
}

sub post_login {
    my($self, $idx, $env) = @_;
    my $session = Plack::Session->new($env);
    my $req = Plack::Request->new($env);
    my $opt = $self->login_spec->[$idx];
    my $uri = $opt->{'uri'};
    my $param = {
        'account' => $session->get('account') || q(),
        'uri.account' => $session->get($uri . '#account') || q(),
        'uri.protect' => $session->get($uri . '#protect') || q(),
        'post.account' => $req->body_parameters->{'account'} || q(),
        'post.password' => $req->body_parameters->{'password'} || q(),
        'post.protect' => $req->body_parameters->{'protect'} || q(),
    };
    if (! $self->check_protect($param)) {
        return $self->redirect_first_phase($req);
    }
    my $auth = $self->authenticate($idx, $req, $param);
    $self->update_session($idx, $env, $auth);
    my $location = ! $auth ? $self->login_spec->[0]{'uri'}
                 : $idx >= $#{$self->login_spec} ? $auth->{'redirect_uri'}
                 : $self->login_spec->[$idx + 1]{'uri'};
    return $self->redirect($req, $location, 303)->finalize;
}

sub call_logout {
    my($self, $env) = @_;
    $self->update_session(0, $env, undef);
    my $req = Plack::Request->new($env);
    my $location = $self->logout_spec->{'redirect_uri'} || q(/);
    return $self->redirect($req, $location, 303)->finalize;
}

sub redirect_first_phase {
    my($self, $req) = @_;
    my $location = $self->login_spec->[0]{'uri'};
    return $self->redirect($req, $location, 303)->finalize;
}

sub redirect {
    my($self, $req, $location, $code) = @_;
    my $res = $req->new_response;
    $res->redirect($location, $code);
    $res->content_type('text/plain; charset=UTF-8');
    $res->body("See ${location}");
    return $res;
}

sub method_not_allowed {
    my($self, $env) = @_;
    my $body = 'method not allowed';
    return [405, [
        'Content-Type' => 'text/plain; charset=UTF-8',
        'Content-Length' => (length $body),
        'Allow' => 'HEAD,GET,POST'
    ], [$body]];
}

1;

__END__

=pod

=head1 NAME

Plack::Middleware::Auth::LoginChain - Multi phase authentication session

=head1 VERSION

0.02

=head1 SYNOPSIS

    use Plack::Builder;
    use MyCrypt;
    
    sub auth_totp {
        my($account, $password, $psgi_env) = @_;
        my $key = $users->{$account}{'totpkey'};
        $password eq MyCrypt->totp_sha1_6(time, $key) or return;
        return {'account' => $account, 'redirect_uri' => "/$account"};
    }
    
    sub auth_xcrypt {
        my($account, $password, $psgi_env) = @_;
        my $crypted = $users->{$account}{'password'};
        $crypted eq MyCrypt->xcrypt($password, $crypted) or return;
        return {'account' => $account, 'redirect_uri' => "/$account"};
    }
    
    sub auth_responder {
        my($plack_request, $param) = @_;
        return [200, ['Content-Type' => 'text/html; charset=UTF-8'],
                     [render_template_as_your_like('login.html', $param)]];
    }
    
    builder {
        enable 'Session';
        enable 'Auth::LoginChain',
            login_spec => [
                {'uri' => '/login',
                 'authenticator' => \&auth_totp,
                 'responder' => \&auth_responder,
                 'realm' => 'One-Time Password'},
                {'uri' => '/login2',
                 'authenticator' => \&auth_xcrypt,
                 'responder' => \&auth_responder,
                 'realm' => 'Password'},
            ],
            logout_spec => {
                'uri' => '/logout',
                'redirect_uri' => '/'
            };
        $myapp;
    };

=head1 DESCRIPTION

Recently, to protect user authentications from attackers, multi-phase
authentication can be used. This Plack Middleware provides you to serve
multi-phase authentication. For examples as synopsis section,
login account is validated with RFC 6238 Time-Based One-Time Password
at first phase, and same account will be validated with normal crypt hash
comparison at second phase. 

=head1 METHODS

=over

=item C<login_spec>

An attribute is the specification of login phases.

    login_spec => [
        {'uri' => '/login',            # required just match PATH_INFO
         'authenticator' => \&authenticator, # required code reference
         'responder' => \&responder,         # required code reference
         'realm' => 'description'},          # recommended scalar
        #...
    ]

=item C<logout_spec>

An attribute is the specification of logout.

    logout_spec => {
        'uri' => '/logout',
        'redirect_uri' => '/'
    }

=item C<prepare_app>

Check constraints of login_spec and logout_spec.
This is called from the ancestor's C<Plack::Component::to_app> method.

=item C<gen_protect>

Generates a random string for after used by C<check_protect>.

=item C<check_protect>

Compares saved protect value and posted one.

=item C<authenticate>

Compares saved account and posted one after first phase.
Invokes the lognin_spec's authenticator function.
This method returns a variant of

    undef | {'account' => $account, 'redirect_uri' => $uri}

=item C<update_session>

Updates the session hash values according to the authentication
results.

=item C<clean_session>

Cleans the session hash values related to login phase states.
Just after this method, all login session starts at the
first phase always.

=item C<call>

Here is the Plack middleware entry point.

=item C<dispatch>

Dispatch some routes for REQUEST_METHOD and PATH_INFO.

=item C<get_login>

Responds GET /loginNth call.
Even if user logged in, any times of re-authentications are allowed.

=item C<post_login>

Authenticates by user's POST form data, account, password, and
protect.

=item C<call_logout>

Stop the current login session. This erases any session data.

=item C<redirect_first_phase>

Drops any login state data from the session, and return back
to the first phase.

=item C<redirect>

See other location for general cases.

=item C<method_not_allowed>

Returns error response for method not allowed of HTTP/1.1.
This erases login phase control data from the session too.

=back

=head1 AUTHOR

MIZUTANI Tociyuki

=head1 LICENSE AND COPYRIGHT

Copyright (c) 2017, MIZUTANI Tociyuki C<< <tociyuki@gmail.com> >>.
All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
