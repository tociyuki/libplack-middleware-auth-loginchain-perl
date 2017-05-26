package MyCrypt;
use strict;
use warnings;
use POSIX ();
use Digest::SHA qw(hmac_sha1_hex hmac_sha256);
use MIME::Base64 qw(encode_base64url);

our $VERSION = '0.01';

sub totp_sha1_6 {
    my($class, $unix_time, $key) = @_;
    my $t = POSIX::floor($unix_time / 30);
    my $message = pack "NN", int($t / 4294967296.0), int($t % 4294967296.0);
    my $hash = hmac_sha1_hex($message, $key);
    my $off = hex substr $hash, -1;
    my $bin0 = (hex substr $hash, $off * 2, 1) & 7;
    my $bin = $bin0 . (substr $hash, $off * 2 + 1, 7);
    return sprintf "%06d", (hex $bin) % 1000000;
}

sub xcrypt {
    my($class, $plain, $secret) = @_;
    my($salt, $strech) = split m/\$/msx, $secret, 2;
    return join q($), $salt, $class->pbkdf2_sha256($plain, $salt);
}

sub pbkdf2_sha256 {
    my($class, $plain, $salt) = @_;
    my $cost = 1 << 10;
    my $dklen = 48;
    my $dk = q();
    my $i = 0;
    while ($dklen > 0) {
        my $u = hmac_sha256($salt . pack('N', ++$i), $plain);
        my $t = $u;
        for (2 .. $cost) {
            $u = hmac_sha256($u, $plain);
            $t ^= $u;
        }
        my $n = $dklen < (length $t) ? $dklen : (length $t);
        $dk .= substr $t, 0, $n;
        $dklen -= $n;
    }
    return encode_base64url($dk);
}

1;
