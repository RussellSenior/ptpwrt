#
# LDAP.pm for NoCat
#
#	This is the Source module to interface to LDAP directories.
#
#	This has currently been built to work against a Novell eDirectory LDAP service.  Some
#	of the functions might contain attributes or interactions that will have to be altered
#	for other LDAP directories.  This is not a Novell issue, it is a LDAP standards issue.
#	All attempts should be made to isolate and note any of the directory dependencies.
#	SCL 2002-06-05
#
# SCL - 2002-06-07	made Net::LDAPS (SSL) the default package
#			added nocat.conf option for hashing passwords
#			added nocat.conf option for requiring admin auth for all operations
#
#	TODO: Complete the store_user() function ...
#	TODO: Complete change password for LDAP ...
#	TODO: Add a separate "Search_Base" unique from "Create_Base" for shared directories
#	TODO: Verify the operation of groups!
#	TODO: Address the functions in the POD
#
package NoCat::Source::LDAP;

use NoCat::Source;
# SCL - 2002-06-07 All LDAP users *should* consider using the SSL package since
#	information is being passed in forms that can be grabbed off the wire!
use Net::LDAPS;
# SCL - 2002-06-05 Added the MD5 modules for hashing passwords
use Digest::MD5 qw( md5_base64 );
use strict;
use vars qw( @ISA @REQUIRED );

@ISA	    = qw( NoCat::Source );
@REQUIRED   = qw(
    LDAP_Host LDAP_Base LDAP_Admin_User LDAP_Admin_PW LDAP_Filter
    UserIDField GroupTable GroupIDField GroupAdminField
);


sub ldap {
    my ($self) = @_;
    unless ($self->{LDAP}) {
	my $ldap = Net::LDAP->new( $self->{LDAP_Host} );
	if ($ldap) {
	    $self->{LDAP} = $ldap;
	} else {
	    $self->log( 0, "Can't connect to LDAP server $self->{LDAP_Host}" );
	}
    }
    return $self->{LDAP};
}


# dn()	retrieves the LDAP distinguished name of a user, using the
#	username provided.  It does this by searching on the
#	LDAP_Filter attribute in the directory.
#
# SCL -	2002-06-05 Updated dn() to lookup the distinguished name of a user
#                  who has the LDAP_Filter attribute equal to the value provided
#                  in the login web page
#
sub dn {
    my ($self,$user_id) = @_;

    my $filter = $self->{LDAP_Filter} . "=" . $user_id;

    my $mesg = $self->ldap->search(
	        base   => $self->{LDAP_Base},
        	filter => $filter
    );

    # Check to see if any entries were returned ...
    if ($mesg->count > 0) {
    	# If one or more were there, grab the LDAP_Filter attribute value of the first
    	my $entry = $mesg->entry(0);
	my $dn = $entry->dn;
	return $dn;
    } else {
    	# If none were found, return nothing ...
    	return{};
    }
}


# create() stores a new NoCat::User object after it's been populated.
#
# SCL -	2002-06-05 Updated create() to perform the following actions:
#
#	1. Added the bind to the LDAP directory as a user with administrative rights.
#	2. The user will be created in the LDAP_Base container, using the "Name"
#	   provided by the user.
#	3. E-Mail address is stored in the e-mail attribute.
#	4. Other attributes are placed in searchable LDAP attributes.
#	5. Passwords are hashed before being used.
#	6. For debugging, all other information can be stored in the 'description' attribute
#	NOTE:  The password will be stored in clear text in the description attribute if you
#		enable this for debugging!  An obvious security hole ...
#
#	NOTE:	If you DO NOT want the passwords to be set in MD5 hashed format then
#		you will have to set the option LDAP_HashPasswords in the nocat.conf file to be
#		"no".  There are cases where you might want to do this to preserve existing
#		passwords that would be used from other LDAP client applications or services.
#
sub create_user {
    my ( $self, $user )	= @_;

    # Clear the user timestamp.
    $user->set( $self->{UserStampField} => undef )
	if $self->{UserStampField};

    # If we are hashing the passwords, make sure the user's password is crypted.
    if ($self->{LDAP_Hash_Passwords} eq "Yes") {
    	$self->check_password( $user );
    }

    # Add the data to the database.
    #
    my %data = %{ $user->data };
    # SCL - NOTE: these next lines might no longer be required ...
    #	I obviously have to learn more Perl ...  ;-)
    my @fields	= keys %data;
    my @place	= ("?") x @fields;

    # Bind as an administrative user with the rights to create users
    my $result = $self->ldap->bind( 'dn' => $self->{LDAP_Admin_User}, 'password' => $self->{LDAP_Admin_PW});

    # Add the user to the directory ...
    #
    $result = $self->ldap->add(
    		# Use the "Name" as the distinguished name, concatenated with LDAP_Base
    		'dn' => 'cn=' . $data{"Name"} . ',' . $self->{LDAP_Base},
		attr => [
			# Put all of the user information into the description
			#	attribute for debugging ...
			#'description' => [map { "$_ => $data{$_}," } keys %data],

			# Set the description to be the user provided text ...
			'description' => $data{"Description"},

			# Set the surname to "Name"
			'sn' => $data{"Name"},

			# Set the mail attribute ...
			$self->{LDAP_Filter} => $user->id,

			# Put the user's URL into the Location attribute
			'l' => $data{"URL"},

			# Set the user's password ...
			#
			#	This might have to change based on the LDAP directory.
			#
			#	This has been tested and works with Novell eDirectory
			#	although in reading docs of many LDAP servers the attribute
			#	name might change ...
			#
			'userPassword' => $data{"Pass"},

			# Set the object class for creation ...
			'objectclass' =>
				['top',
				 'person',
				 'organizationalPerson',
				 'inetOrgPerson'
				 ],
			]
		);
    # Unbind the administrative user ... bind Anonymous ...
    $self->ldap->bind;
}


# store()	updates the user information
#
# SCL -	2002-06-05 NOTE: This is not yet operational!!!
#
sub store_user {
    my ( $self, $user )	= @_;
    my $data	= $user->data;
    my $fields	= $self->where( "," => keys %$data );

    #local $" = ", ";
    #$self->ldap->modify( $self->dn($user->id, attr => %$data);
}


# check_password()	will MD5 the password if it in not already ...
#
sub check_password {
    my ($self, $user) = @_;
    # MD5 the password if it's not already MD5'd, prior to actually using it.
    $user->set_password( md5_base64( $user->passwd ), 1 ) if $user->changed_password;
    return $user->passwd;
}


# authenticate_user()	verifies the credentials of the user by:
#
# SCL - 2002-06-07	added admin bind and hashing option support
# SCL -	2002-06-05	rewrote the function to perform the following:
#
#	1. If searching as admin, bind as admin
#	1. lookup the distinguished name of the user using the e-mail attribute
#	2. If hashing passwords, MD5 hash the password if it isn't already
#	3. bind as the user/pw and see if it works!
#
sub authenticate_user {
    my ($self, $user_pw, $user) = @_;
    my $retval = 0;

    # If LDAP_Search_as_Admin is true, then bind as the administrative user
    if ($self->{LDAP_Search_as_Admin} eq "Yes") {
    	my $result = $self->ldap->bind( 'dn' => $self->{LDAP_Admin_User}, 'password' => $self->{LDAP_Admin_PW});
    }

    # Get the distinguished name ...
    my $username = $self->dn($user->id);

    # Get the password provided through the web page ...
    my $md5_pw = $user_pw;

    # If hashing passwords, then MD5 hash it before using it ...
    if ($self->{LDAP_Hash_Passwords} eq "Yes") {
    	$md5_pw = md5_base64( $user_pw );
    }

    # Bind as the user ... see if it works ...
    my $result = $self->ldap->bind( $username, 'password' => $md5_pw);
    if($result->code == 0) {
	# Yep ... we're there ...
	$retval = 1;
    }

    # Unbind the administrative user ... bind Anonymous ...
    $self->ldap->bind;

    return $retval;
}

# fetch_user_by_id()	finds a user with the provided e-mail address ... if they exist!
#
# SCL -	2002-06-05	rewrote the function to:
#
#	1. search based on the e-mail attribute
#	2. deal with the fact that no entries might be returned ...
#
sub fetch_user_by_id {
    my ( $self, $id )    = @_;

    # If LDAP_Search_as_Admin is true, then bind as the administrative user
    if ($self->{LDAP_Search_as_Admin} eq "Yes") {
    	my $result = $self->ldap->bind( 'dn' => $self->{LDAP_Admin_User}, 'password' => $self->{LDAP_Admin_PW});
    }

    my $filter = $self->{LDAP_Filter} . "=" . $id;
    # Search for a user with the right e-mail address ...
    my $mesg = $self->ldap->search(
				   base   => $self->{LDAP_Base},
				   filter => $filter
				   );

    # Unbind the administrative user ... bind Anonymous ...
    if ($self->{LDAP_Search_as_Admin} eq "Yes") {
    	$self->ldap->bind;
    }

    # Check to see if any entries were returned ...
    if ($mesg->count > 0) {
    	# If one or more were there, grab the e-mail attribute value of the first
    	my $entry = $mesg->entry(0);
	return { $self->{UserIDField} => $entry->get_value($self->{LDAP_Filter}) };
    } else {
    	# If none were found, return nothing ...
    	return{};
    }
}


# fetch_groups_by_user()
#
# SCL -	2002-06-05	modified this to use dn() to translate the e-mail to a distinguished name
#
#	NOTE: The modification was to correct an error that was crashing the script, however
#		the overall group support was not verified ...
#
sub fetch_groups_by_user {
    my ( $self, $user ) = @_;
    my %data;

    # If LDAP_Search_as_Admin is true, then bind as the administrative user
    if ($self->{LDAP_Search_as_Admin} eq "Yes") {
    	my $result = $self->ldap->bind( 'dn' => $self->{LDAP_Admin_User}, 'password' => $self->{LDAP_Admin_PW});
    }

    # Set $uid to be the distinguished name based on a e-mail address lookup
    my $uid = $self->dn($user->id);

    # Search for the groups that
    my $mesg = $self->ldap->search(
				   base => $self->{LDAP_Base},
				   filter => "memberUID='$uid'"
				   );

    foreach my $entry ($mesg->all_entries) {
	$data{$entry->get_value('gidNumber')} = 1;
    }

    # Unbind the administrative user ... bind Anonymous ...
    if ($self->{LDAP_Search_as_Admin} eq "Yes") {
    	$self->ldap->bind;
    }

    return \%data;
}

# fetch_users_by_group()
#
# SCL -	2002-06-05	didn't verify this one ... yet ...
#
sub fetch_users_by_group {
    my ( $self, $group ) = @_;
    my %data;
    my $gid = $group->id;
    my $mesg = $self->ldap->search(
				   base => $self->{LDAP_Base},
				   filter => "gidNumber=$gid"
				   );
    foreach my $entry ($mesg->all_entries) {
	foreach my $user ($entry->get_value('memberUID')) {
	    $data{$user} = 1;
	}
    }
    return \%data;
}

=pod

These need to be implemented for the admin interface to work.
(Or get a real LDAP browser! :-)

sub add_group_member {
    my ( $self, $group, $user, $admin ) = @_;

}

sub drop_group_member {
    my ( $self, $group, $user ) = @_;
}

sub update_group_member {
    my ( $self, $group, $user, $admin ) = @_;

}

# Some modifications and additions done by:
#
#  SCL - Scott C. Lemon  http://www.HumanXtensions.com  info@HumanXtensions.com
#

=cut

1;

