package Mustache::Tiny;
use strict;
use warnings;
use Plack::Util;

our $VERSION = '0.01';

sub subst {
    my($self, $body, $param) = @_;
    $body =~ s{
        \{\{(?:\s*([A-Za-z0-9\-_.]+)\s*\}\}
            |\{\s*([A-Za-z0-9\-_.]+)\s*\}\}\}
            |\s*\#(([A-Za-z0-9\-_.]+)(?:[:][0-9])?)\s*\}\}\n?
                (.*?)\{\{\s*/\3\s*\}\}
            |\s*\^(([A-Za-z0-9\-_.]+)(?:[:][0-9])?)\s*\}\}\n?
                (.*?)\{\{\s*/\6\s*\}\}
            )\n?
    }{
        defined $1 ? Plack::Util::encode_html(
            defined $param->{$1} ? $param->{$1} : q())
      : defined $2 ? (defined $param->{$2} ? $param->{$2} : q())
      : defined $4 ? $self->subst_block($4, $5, $param)
      : $self->subst_hat($7, $8, $param)
    }egmsx;
    return $body;
}

sub subst_block {
    my($self, $key, $body, $param) = @_;
    my $content = q();
    if ('HASH' eq ref $param->{$key}) {
        if (%{$param->{$key}}) {
            $content .= $self->subst($body, {%{$param}, %{$param->{$key}}});
        }
    }
    elsif ('ARRAY' eq ref $param->{$key}) {
        for my $hashref (@{$param->{$key}}) {
            $content .= $self->subst($body, {%{$param}, %{$hashref}});
        }
    }
    elsif ($param->{$key}) {
        $content .= $self->subst($body, $param);
    }
    return $content;
}

sub subst_hat {
    my($self, $key, $body, $param) = @_;
    my $content = q();
    if (! $param->{$key}) {
        $content .= $self->subst($body, $param);
    }
    elsif ('HASH' eq ref $param->{$key}) {
        if (! %{$param->{$key}}) {
            $content .= $self->subst($body, $param);
        }
    }
    elsif ('ARRAY' eq ref $param->{$key}) {
        if (! @{$param->{$key}}) {
            $content .= $self->subst($body, $param);
        }
    }
    return $content;
}

1;
