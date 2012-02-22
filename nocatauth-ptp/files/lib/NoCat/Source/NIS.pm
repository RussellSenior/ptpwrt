package NoCat::Source::NIS;

# Contributed by Olivier Page <olivier (DOT) page (AT) esm2.imt-mrs.fr>

use NoCat::Source;
use Net::NIS;
use strict;
use vars qw( @ISA  );

@ISA        = qw( NoCat::Source );

sub authenticate_user {

     my ($self, $user_pw, $user) = @_;
     my $id = $user->id;
     my $domain = Net::NIS::yp_get_default_domain();
     unless($domain) {
         $self->log(1,"Unable to determine domain name");
         return 0;
         }
     my( $status,$entry ) = Net::NIS::yp_match($domain,"passwd.byname",
                         $id );
     if($status) {
         $self->log( 5, "auth_nis failed to find user ", $id );
         return 0;
         }
     my($nisuser,$hash,$uid,$gid,$gecos,$dir,$shell) = split(/:/,$entry);
     my $result = crypt($user_pw, $hash) eq $hash;
     if ($result == 1) {
         return 1;
     } else {
         return $self->log( 4, "NIS returned $result for user $id" );
     }


}


1;


