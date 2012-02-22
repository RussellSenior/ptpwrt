use strict;
package NoCat::BrowserDetect;
BEGIN {
  $NoCat::BrowserDetect::VERSION = '1.12';
}

use vars qw(@ISA @EXPORT @EXPORT_OK @ALL_TESTS);
require Exporter;

@ISA       = qw(Exporter);
@EXPORT    = qw();
@EXPORT_OK = qw();

# Properties
push @ALL_TESTS, 'mobile';

#######################################################################################################
# BROWSER OBJECT

my $default = undef;

sub new {
    my ( $class, $user_agent ) = @_;

    my $self = {};
    bless $self, $class;

    unless ( defined $user_agent ) {
        $user_agent = $ENV{'HTTP_USER_AGENT'};
    }

    $self->user_agent( $user_agent );
    return $self;
}

foreach my $test ( @ALL_TESTS ) {
    no strict 'refs';
    my $key = uc $test;
    *{$test} = sub {
        my ( $self ) = _self_or_default( @_ );
        return $self->{tests}->{$key};
    };
}

sub _self_or_default {
    my ( $self ) = $_[0];
    return @_
        if ( defined $self
        && ref $self
        && ( ref $self eq 'NoCat::BrowserDetect' )
        || UNIVERSAL::isa( $self, 'NoCat::BrowserDetect' ) );
    $default ||= NoCat::BrowserDetect->new();
    unshift( @_, $default );
    return @_;
}

sub user_agent {
    my ( $self, $user_agent ) = _self_or_default( @_ );
    if ( defined $user_agent ) {
        $self->{user_agent} = $user_agent;
        $self->_test();
    }
    return $self->{user_agent};
}

# Private method -- test the UA string
sub _test {
    my ( $self ) = @_;

    $self->{tests} = {};
    my $tests = $self->{tests};

    my $ua = lc $self->{user_agent};

    # Devices
    $tests->{MOBILE} = (
               index( $ua, "up.browser" ) != -1
            || index( $ua, "kindle" ) != -1
	    || index( $ua, "nokia" ) != -1
            || index( $ua, "alcatel" ) != -1
            || index( $ua, "ericsson" ) != -1
            || index( $ua, "sie-" ) == 0
            || index( $ua, "wmlib" ) != -1
            || index( $ua, " wap" ) != -1
            || index( $ua, "wap " ) != -1
            || index( $ua, "wap/" ) != -1
            || index( $ua, "-wap" ) != -1
            || index( $ua, "wap-" ) != -1
            || index( $ua, "wap" ) == 0
            || index( $ua, "wapper" ) != -1
            || index( $ua, "blackberry" ) != -1
            || index( $ua, "iemobile" ) != -1
            || index( $ua, "palm" ) != -1
            || index( $ua, "smartphone" ) != -1
            || index( $ua, "windows ce" ) != -1
            || index( $ua, "palmsource" ) != -1
            || index( $ua, "iphone" ) != -1
            || index( $ua, "ipod" ) != -1
            || index( $ua, "ipad" ) != -1
            || index( $ua, "opera mini" ) != -1
            || index( $ua, "android" ) != -1
            || index( $ua, "htc_" ) != -1
            || index( $ua, "symbian" ) != -1
            || index( $ua, "webos" ) != -1
            || index( $ua, "samsung" ) != -1
            || index( $ua, "samsung" ) != -1
            || index( $ua, "zetor" ) != -1
            || index( $ua, "android" ) != -1
            || index( $ua, "symbos" ) != -1
            || index( $ua, "opera mobi" ) != -1
    );

};
1;
