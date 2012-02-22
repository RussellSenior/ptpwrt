package NoCat::Message;

use NoCat;
use IPC::Open3;
use strict;
use vars qw( @ISA *IN *OUT *ERR );

@ISA = 'NoCat';

sub text {
    my ( $self, $txt ) = @_;
    if ( defined $txt ) {
	$self->{Signed} = $self->{Verified} = 0;
	$self->{Msg} = $txt;
    }
    $self->{Msg}
}

sub sign { 
    my $self = shift; 
    $self->pgp( Sign => @_ ) 
}

sub encode { 
    my $self = shift; 
    $self->pgp( Encode => @_ )
}

sub decode { 
    my $self = shift; 
    $self->pgp( Decode => @_ ) 
}

my %Cmd_Map = (
    Encode => "--sign --armor",
    Decode => "--decrypt",
    Sign   => "--clearsign"
);

sub pgp {
    my ( $self, $cmd, $txt ) = @_;

    return $self->text if $self->{Signed} and not defined $txt;
    $txt = $self->text( $txt );

    if ( my $directive = $self->{"Message$cmd"} ) {
	$cmd = $self->SUPER::format( $directive );

    } elsif ( $self->{GpgPath} and $self->{PGPKeyPath} and $Cmd_Map{$cmd} ) {
	$cmd = "$self->{GpgPath} $Cmd_Map{$cmd} --homedir=$self->{PGPKeyPath} " .
	    "--keyring trustedkeys.gpg --no-tty -o-";
	$cmd .= " 2>/dev/null" if $self->{Verbosity} < 7;

    } else {
	die "Can't find required Message$cmd directive";
    }

    local $SIG{CHLD} = "DEFAULT";

    my $pid = open3( \*OUT, \*IN, \*ERR, $cmd ) or die "$cmd: $!";
    print OUT $txt;
    close OUT;  

    $txt = do { local $/ = undef; <IN> };
    close IN;

    my $err = do { local $/ = undef; <ERR> };
    close ERR;
    $self->log( 1, "$cmd returned error message:\n$err" ) if $err;

    if (waitpid($pid, 0) == -1 or $? >> 8 != 0) {
	$self->log( 1, "$cmd returned error: $! (", $? >> 8, ")" );
	return;
    }

    $self->{Signed}++;
    $self->text( $txt );
    return $self;
}

sub verify {
    my ( $self, $txt ) = @_;
    my $cmd;

    return $self->text if $self->{Verified} and not defined $txt;
    $txt = $self->text( $txt );

    if ( $self->{MessageVerify} ) {
	$cmd = $self->{MessageVerify} 
    
    } elsif ( $self->{GpgvPath} and $self->{PGPKeyPath} ) {
	$cmd = '$GpgvPath --homedir=$PGPKeyPath';
	$cmd .= ' 2>/dev/null' if $self->{Verbosity} < 7;

    } else {
	die "Can't find required MessageVerify directive";
    }

    $cmd = $self->SUPER::format( $cmd );
    
    local $SIG{CHLD} = "DEFAULT";

    my $kid = open OUT, "|-";
    if ( not defined $kid ) {
	die "$cmd: fork failure";
    } elsif ( not $kid ) {
	exec $cmd;
    }
    print OUT $txt;
    close OUT;

    if (my $result = ( $? >> 8 )) {
	return $self->log( 1, "$cmd returned $result" );
    } else { 
	return 1;
    }
}

sub extract {
    my $self = shift;
    my $txt = $self->text;

    if ( $txt =~
	/-+BEGIN PGP [A-Z ]+-+.*?\n\n(.*?\n)-+[A-Z]+ PGP [A-Z ]+-+/os ) {
	return $1;
    } else {
	return $txt;
    }
}

sub parse {
    my ( $self, $text ) = @_;
    return $self->SUPER::parse( $self->extract( $text ) );
}

sub format {
    my ( $self, %args ) = @_;
    $self->text( $self->deparse( %args ) );
    return $self;
}

1;
