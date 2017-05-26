use 5.010;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Plack::Middleware::Auth::LoginChain',
    AUTHOR           => q{MIZUTANI Tociyuki <tociyuki@gmail.com>},
    VERSION_FROM     => 'lib/Plack/Middleware/Auth/LoginChain.pm',
    ABSTRACT_FROM    => 'lib/Plack/Middleware/Auth/LoginChain.pm',
    LICENSE          => 'artistic_2',
    PL_FILES         => {},
    MIN_PERL_VERSION => '5.010',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '0',
    },
    BUILD_REQUIRES => {
        'Test::More' => '0',
        'HTTP::Request::Common' => '0',
    },
    PREREQ_PM => {
        'Plack'             => '1.0044',
        'Crypt::OpenSSL::Random' => '0.11',
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Plack-Middleware-Auth-LoginChain-*' },
);
