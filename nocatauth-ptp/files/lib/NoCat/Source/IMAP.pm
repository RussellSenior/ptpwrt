package NoCat::Source::IMAP;

use NoCat::Source;
use Net::IMAP::Simple; 
use strict;
use vars qw( @ISA );

@ISA = qw( NoCat::Source );

sub authenticate_user {
    my ($self, $user_pw, $user) = @_;
    $user = $user->id;

    my $server = new Net::IMAP::Simple( $self->{IMAP_Server} );

    if( $server->login( $user,$user_pw ) )
    {
      $server->quit;
      return 1;
    } else {
      $self->log( 4, "Tried to auth via " . $self->{IMAP_Server} );
      $server->quit;
      return $self->log( 4, "IMAP authentication unsuccessful." );
    }

}

1;

