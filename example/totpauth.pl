use strict;
use warnings;
use Carp;
use Getopt::Long;
use Pod::Usage;
use IO::Handle;
use POSIX ();
use Digest::SHA qw(hmac_sha1_hex hmac_sha256_hex hmac_sha512_hex);
use File::Slurp;

my %HASH_FUNC = (
    'sha1'   => \&hmac_sha1_hex,
    'sha256' => \&hmac_sha256_hex,
    'sha512' => \&hmac_sha512_hex,
);
my $help = 0;
GetOptions('help' => \$help) or pod2usage(2);
pod2usage(1) if $help;

my $keyname = shift @ARGV or pod2usage(2);
my $keysrc = read_file($keyname) or croak "read:key file: $!\n";

my($issure_path, $account, $query) = $keysrc =~ m{
    \Aotpauth://totp/([^:]+):([^?]+)[?](.*)\z
}msx or croak "invalid otpauth key";
$issure_path = decode_url($issure_path);
$account = decode_url($account);
my $param = {};
for my $pair (split m/[&]/msx, $query) {
    my($key, $value) = split m/[=]/msx, $pair, 2;
    $key = decode_url($key);
    $value = decode_url($value);
    $param->{$key} = $value;
} 

$param->{'secret'} or croak "invalid otpauth key:required secret.";
my $key = decode_base32($param->{'secret'});
my $algorithm = lc ($param->{'algorithm'} || q(sha1));
my $digits = $param->{'digits'} || 6;
my $period = $param->{'period'} || 30;
print "$key $algorithm $digits $period\n";

if ($issure_path || $param->{'issure'}) {
    print q(), $param->{'issure'} || $issure_path, ":";
}
print $account, "\n";
STDOUT->autoflush(1);
while (1) {
    my $time = time;
    my $otp = totp($time, $key, $algorithm, $digits, $period);
    print "\r$otp  |";
    my $sec = $time % $period;
    print " " x $sec, "*" x ($period - $sec), "|";
    sleep 1;
}

# RFC 6238 TOTP: Time-Based One-Time Password Algorithm
sub totp {
    my($unix_time, $key, $algorithm, $digits, $period) = @_;
    $algorithm ||= 'sha1';
    $algorithm = ($algorithm eq 'sha256') || ($algorithm eq 'sha512')
        ? $algorithm : 'sha1';
    $digits ||= 6;
    $digits = $digits == 6 ? 6 : 8;
    $period ||= 30;
    my $t = POSIX::floor($unix_time / $period);
    my $message = pack "NN", int($t / 4294967296.0), int($t % 4294967296.0);
    my $hash = $HASH_FUNC{$algorithm}->($message, $key);
    my $off = hex substr $hash, -1;
    my $bin0 = (hex substr $hash, $off * 2, 1) & 7;
    my $bin = $bin0 . (substr $hash, $off * 2 + 1, 7);
    my $mask = $digits == 6 ? 1000000 : 100000000;
    return sprintf "%0${digits}d", (hex $bin) % $mask;
}

# RFC 3548 The Base32 encoding
sub decode_base32 {
    my($src, $autopadding) = @_;
    my $dst = q();
    my $i = 0;
    my $k = 0;
    my @u = (0, 0, 0, 0, 0);
    while ($i < (length $src) && (substr $src, $i, 1) ne q(=)) {
        my $ch = substr $src, $i++, 1;
        my $d = ('A' le $ch && $ch le 'Z') ? (ord $ch) - (ord 'A')
              : ('2' le $ch && $ch le '7') ? (ord $ch) - (ord '2') + 26
              : -1;
        next if $d < 0;
        my $k64 = (7 - $k) * 5;
        my $offset = 4 - int($k64 / 8);
        my $count = $k64 % 8;
        if (8 - $count < 5) {
            $u[$offset - 1] |= $d >> (8 - $count);
        }
        $u[$offset] |= ($d << $count) & 0xff;
        if (++$k > 7) {
            $dst .= pack "CCCCC", @u;
            @u = (0, 0, 0, 0, 0);
            $k = 0;
        }
    }
    my $npadding = 0;
    while ($i < (length $src)) {
        if ((substr $src, $i, 1) eq q(=)) {
            ++$npadding;
        }
        ++$i;
    }
    $k = $k == 0 ? 8 : $k;
    if (1 == $k || 3 == $k || 6 == $k || $npadding > 6) {
        croak "Invalid Base32";
    }
    if ((! $autopadding || $npadding > 0) && $k + $npadding != 8) {
        croak "Invalid Base32";
    }
    $npadding = 8 - $k;
    if (0 < $npadding) {
        $dst .= pack "C", $u[0];
    }
    if (0 < $npadding && $npadding < 5) {
        $dst .= pack "C", $u[1];
    }
    if (0 < $npadding && $npadding < 4) {
        $dst .= pack "C", $u[2];
    }
    if (1 == $npadding) {
        $dst .= pack "C", $u[3];
    }
    return $dst;
}

sub decode_url {
    my($s) = @_;
    $s =~ y/+/ /;
    $s =~ s{%([0-9A-Fa-f]{2})}{ chr hex $1 }egmsx;
    return $s;
}

__END__

=head1 NAME

totp - RFC 6238 Time-Based One-Time Password Generator

=head1 SYNOPSIS

    totp [options] keyfilename
    
    Options:
      --six     six digits password (default)
      --eight   eight digits password
      --sha1    SHA-1 (default)
      --sha256  SHA-256
      --sha512  SHA-512
      --help    print this message

=head1 OPTIONS

=over

=item B<--six>

generate 6 digits Time-Based One-Time Password.

=item B<--eight>

generate 8 digits Time-Based One-Time Password.

=item B<--sha1>

switch algorithm to SHA-1 (default).

=item B<--sha256>

switch algorithm to SHA-256.

=item B<--sha512>

switch algorithm to SHA-512.

=back

=head1 DESCRIPTION

This program generates Time-Based One-Time Password for you.
It is neccessary to specify Google-Authenticator's Key URI Format file.

C<otpauth://totp/Example:alice@example.net?secret=PBHWM6TSGJMEGZRU&issuer=Example>

=head1 SEE ALSO

RFC 6238 TOTP: Time-Based One-Time Password Algorithm

RFC 3548 The Base32 encoding

L<https://github.com/google/google-authenticator/wiki/Key-Uri-Format>

=head1 AUTHOR

MIZUTANI Tociyuki

=head1 LICENSE AND COPYRIGHT

Copyright (c) 2017, MIZUTANI Tociyuki C<< <tociyuki@gmail.com> >>.
All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
