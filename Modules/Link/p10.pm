# P10 module - supports Undernet (IRCu), QuakeNet (asuka), beware ircd,
# 	       Nefarious, etc.
# note that P10 uses tokenisation internally to represent nicknames and
# server names so if you use &rawirc in a scan module, it'll break with
# the p10 module. let that serve as a warning to only stick to the
# abstraction layer provided! (which in this case will transparently
# convert to and from tokenisation for you...)
#
# Programmed by C.J.Edwards (aka Brain)
# Modifications by Reed Loden (aka reed), Compy, and jm^
# $Id: p10.pm 1619 2005-07-28 22:22:07Z reed $

use warnings;
use MIME::Base64 ();

my %hosts = ();
my %nickhash = ();
my %rnickhash = ();
my %serverids = ();

my $acknowledged = 0;
my $mychants = 0;

my $servnumeric = $numeric;
my $parentserver = $numeric;

sub link_init
{
        if (!main::depends("core-v1")) {
                print "This module requires version 1.x of defender.\n";
                exit(0);
        }
        main::provides("server","p10-server","native-gline","encoded");
	if ($numeric !~ /^[][A-Za-z0-9]{2}$/) {
		print "\n\nYour server numeric doesn't look quite right.\n";
		print "Edit your configuration again, and set your server\n";
		print "to an alphanumeric value of two characters in length\n";
		print "for example \"Ac\" or \"0t\".\n\n";
		exit(0);
	}
}

sub rawirc
{
	my $out = $_[0]; $out .= "\n\r";
	syswrite(SH, $out, length($out));
	print ">> $out\n" if $debug;
}


sub privmsg
{
	my $nick = $_[0];
	if ($nick !~ /^(#|&).+/) { # we aren't messaging a channel, turn it into a nickhash
		$nick = $rnickhash{lc($nick)};
	}
	my $first = $servnumeric."AAA P $nick :$_[1]\n\r";
	syswrite(SH, $first, length($first));
	print ">> $first" if $debug;
}


sub notice
{
	my $nick = $_[0];
	if ($nick !~ /^(#|&).+/) { # we aren't noticing a channel, turn it into a nickhash
		$nick = $rnickhash{lc($nick)};
	}
	my $msg = $_[1];
	my $first = $servnumeric."AAA O $nick :$msg\n\r";
	syswrite(SH, $first, length($first));
	print ">> $first" if $debug;
}

sub message
{
	my $line = shift;
	$line = $servnumeric."AAA P $mychan :$line";
	&rawirc($line);
}

sub globops
{
	my $msg = shift;
	&rawirc("$servnumeric WA :$msg");
}

sub message_to
{
	# messages a nick only...
	my ($dest,$line) = @_;
	$dest = $rnickhash{lc($dest)};
	$line = $servnumeric."AAA P $dest :$line";
	&rawirc($line);
}

sub mode
{
	my ($dest,$line) = @_;
	$line = $servnumeric." M $dest :$line";
	&rawirc($line);
}


sub killuser
{
	my ($nick,$reason) = @_;
	my ($host) = main::gethost($nick);
	if (main::depends("exempt") && Modules::Scan::exempt::hasexempt($host)) {
		&message("\002[EXEMPT]\002 Rejected killuser() for $nick for $reason");
        } else {
		$nick = $rnickhash{lc($nick)}; # turn the nick into a numeric
		&rawirc($servnumeric."AAA D $nick :$botnick ($reason)");
		$KILLED++;
	}
}

sub gline
{
	my ($hostname,$duration,$reason) = @_;
	if (main::depends("exempt") && Modules::Scan::exempt::hasexempt($hostname)) {
		&message("\002[EXEMPT]\002 Rejected gline() for $hostname for $reason");
        } else {
		&rawirc("$servnumeric GL * +$hostname $duration :$reason");
		$KILLED++;
	}
}

sub gethost
{
	my ($nick) = @_;
	$nick = lc($nick);
	return $hosts{$nick}{host};
}

sub getmatching
{
	my @results = ();
	my ($re) = @_;
	foreach my $mask (%hosts)
	{
		if (defined($hosts{$mask}{host}))
		{
			if ($hosts{$mask}{host} =~ /$re/i)
			{
				push @results, $mask;
			}
		}
	}
	return @results;
}

sub connect {
	$CONNECT_TYPE = "Server";

	$acknowledged = 0;

	print ("Creating socket...\n");
	socket(SH, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || print "socket() failed: $!\n";
	if (defined($main::dataValues{"bind"}))
	{
		print "Bound to ip address: " . $main::dataValues{"bind"} . "\n";
		bind(SH, sockaddr_in(0, inet_aton($main::dataValues{"bind"})));
	} else {
		bind(SH, sockaddr_in(0, INADDR_ANY));
	}

	print ("Connecting to $server\:$port...\n");
	my $sin = sockaddr_in ($port,inet_aton($server));
	connect(SH,$sin) || print "Could not connect to server: $!\n";

	print ("Logging in...\n");
	&rawirc("PASS :" . $password . "");
	my $now = time;
	&rawirc("SERVER $servername 1 $now $now J10 " . $servnumeric . "H]] +s :$serverdesc");
}

sub reconnect
{
	close SH;
	&connect;
	&poll;
}

my $njtime = time+20;

sub checkmodes
{
	# this sub checks a nick's modes to see if they're an oper or not
	# if they have +o theyre judged as being oper, and are inserted
	# into an @opers list which is used by non-native globops.
	my ($nick,$modes) = @_;
	if ($modes =~ /^\+/) { # adding modes
		if ($modes =~ /^\+.*(o|A).*$/) {
			$hosts{lc($nick)}{isoper} = 1;
		}
	}
	if ($modes =~ /^-/) { # taking modes
		if ($modes =~ /^-.*(o|A).*$/) {
			$hosts{lc($nick)}{isoper} = 0;
		}
	}
}

sub isoper
{
	my ($nick) = @_;
	return ($hosts{lc($nick)}{isoper} == 1);
}

sub poll {

	$KILLED = 0;
	$CONNECTS = 0;

	while (chomp($buffer = <SH>))
	{
		chop($buffer);

		print "<< $buffer\n" if $debug;

	        if ($buffer =~ /^(.+)\sK\s(.+?)\s(.+?)\s:(.+?)$/i)
	        {
				if ($3 eq ($servnumeric."AAA"))
				{
					my $now = time;
	                	        &rawirc($servnumeric."AAA J $mychan $now");
					&rawirc($servnumeric."AAA M $mychan +o " . $servnumeric . "AAA");
				}
	        }

		if ($buffer =~ /^(ERROR|Y)\s:(.+?)$/)
		{
			print "ERROR received from ircd: $2\n";
			print "You might need to check your C/N lines or link block on the ircd, or port number you are using.\n";
			exit(0);
		}

		if ($buffer =~ /^(.+?)\sREHASH\s(.+?)$/)
		{
			my $nick = $nickhash{$1};
			if ($2 eq $servnumeric)
			{
				&globops("Rehashing at the request of \002$nick\002");
				&rehash;
				foreach my $line (@rehash_data) {
					notice($nick,$line);
				}
			}
		}

		if ($buffer =~ /^(.+?)\sN\s(.+?)\s[0-9]+$/)
		{
			my $oldnick = quotemeta($nickhash{$1});
			my $newnick = quotemeta($2);

			$rnickhash{lc($2)} = $1; # update the rnickhash

			foreach my $mod (@modlist)
			{
				eval ("Modules::Scan::" . $mod ."::handle_nick(\"$oldnick\",\"$newnick\")");
			}
		}

		# MJ N Alpha 3 1079579461 ~hal adsl-63-f45-230-226.dsl.snfc21.pacbell.net Afxebi MJAAx :HAL9000: An IRC Bot Odyssey
		# AB N ``{]{{{]\ 1 1079232536 foo 195.20.109.181 DDFG21 ABAAF :foo.org
		if ($buffer =~ /^(.+?)\sN\s(.+?)\s\d+\s\d+\s(.+?)\s(.+?)\s(.+?)\s(.+?)\s(.+?)\s:(.+?)$/)
		{
			@regarray = split(/ /,$buffer);
			$index = 0;
			foreach $element(@regarray) {
				if ($index eq 2) {
					$thenick = $element;
				} elsif ($index eq 5) {
					$theident = $element;
				} elsif ($index eq 6) {
					$thehost = $element;
				} elsif ($index eq 7) {
					$themodes = $element;
				} else {
					if ($element =~ /:/) {
						$rindex = $index;
						$rindex--;
						last;
					}
				}
				$index++;
			}
			$assigned_id = $regarray[$rindex--];
			$base64ip = $regarray[$rindex--];
			$base64ip = MIME::Base64::decode($base64ip);
			$arrlen = $#regarray;
			$thegecos = "";
			(undef,$thegecos) = split(/:/,$buffer,2);
			$theserver_id = $1; # this is a two-char server id, we'll have to look this up in our servers hash
			$theserver = $serverids{$theserver_id}; # ... like this :-)
			$CONNECTS++;
			$hosts{lc($thenick)}{host} = "$theident\@$thehost";
			$hosts{lc($thenick)}{isoper} = 0;
			$nickhash{$assigned_id} = $thenick; # used for future lookups, id -> nick
			$rnickhash{lc($thenick)} = $assigned_id; # used for reverse lookup, nick -> id
			print "Assigned $assigned_id in hash -> $thenick, on server $theserver (SID=$theserver_id)\n" if $debug;
			&checkmodes($thenick,$themodes);
			$thegecos = quotemeta($thegecos);
			$thenick = quotemeta($thenick);
			foreach $mod (@modlist) {
			        my $func = ("Modules::Scan::" . $mod . "::scan_user(\"$theident\",\"$thehost\",\"$theserver\",\"$thenick\",\"$thegecos\",0)");
			        eval $func;
				print $@ if $@;
			}
		}
		elsif ($buffer =~ /^(.+?)\sN\s(.+?)\s\d+\s\d+\s(.+?)\s(.+?)\s(.+?)\s(.+?)\s:(.+?)$/)
		{
			# SIGN-ON
			my $thenick = $2;
			my $theident = $3;
			my $thehost = $4; # this may not be a realhost, Uworld may munge this, so we're gonna store the base64 ip too!
                        my $base64ip = MIME::Base64::decode($5);
                        my $assigned_id = $6; # hash assigned by uplink always represents this user from now on
                        my $thegecos = $7;
			my $theserver_id = $1; # this is a two-char server id, we'll have to look this up in our servers hash
                        my $theserver = $serverids{$theserver_id}; # ... like this :-)
			$CONNECTS++;
			$hosts{lc($thenick)}{host} = "$theident\@$thehost";
			$hosts{lc($thenick)}{isoper} = 0;
			$nickhash{$assigned_id} = $thenick; # used for future lookups, id -> nick
			$rnickhash{lc($thenick)} = $assigned_id; # used for reverse lookup, nick -> id
			print "Assigned $assigned_id in hash -> $thenick, on server $theserver (SID=$theserver_id)\n" if $debug;
			$thegecos = quotemeta($thegecos);
			$thenick = quotemeta($thenick);
			foreach my $mod (@modlist) {
				my $func = ("Modules::Scan::" . $mod . "::scan_user(\"$theident\",\"$thehost\",\"$theserver\",\"$thenick\",\"$thegecos\",0)");
				eval $func;
				print $@ if $@;
			}
		}

		if ($buffer =~ /^(.+?)\sM\s(.+?)\s(.+?)$/)
		{
			my $thenick = $nickhash{$1};
			my $thetarget = $2;
			if ($thetarget =~ /^(#|&)/) {
				$thetarget = $nickhash{$thetarget};
			}
			my $params = $3;
			$params =~ s/^://;
			&checkmodes($thetarget,$params);
			$thenick = quotemeta($thenick);
			$thetarget = quotemeta($thetarget);
			$params = quotemeta($params);
			foreach my $mod (@modlist) {
				my $func = ("Modules::Scan::" . $mod . "::handle_mode(\"$thenick\",\"$thetarget\",\"$params\")");
				eval $func;
			}
		}

		# :[Brain] KILL Defender :NetAdmin.chatspike.net![Brain] (kill test)
		if ($buffer =~ /^(.+?)\sD\s(.+?)\s:(.+?)$/)
		{
			my $killedby = $1;
			my $killnick = $nickhash{$2};
			my $killreason = $3;
			if (lc($killnick) eq lc($botnick))
			{
				my $now = time;
				&rawirc("$servnumeric N $botnick 1 $now $botnick $domain +iok AAAAAA " . $servnumeric . "AAA :$botname");
				&rawirc($servnumeric."AAA J $mychan $now");
				&rawirc($servnumeric."AAA M $mychan +o " . $servnumeric . "AAA");
			}
		}

		if ($buffer =~ /^(.+?)\sQ\s:(.+?)$/)
		{
			my $quitnick = $nickhash{$1};
			my $quitreason = $2;
			delete $hosts{$quitnick}{host};
			delete $hosts{$quitnick}{isoper};
			delete $nickhash{$1};
			delete $rnickhash{lc($quitnick)};
		}

		if ($buffer =~ /^(.+?)\sB\s(.+?)\s(.+?)\s+(.+?)$/)
		{
			my $thetarget = $2;
			if (lc($thetarget) eq lc($mychan)) {
				$mychants = $3;
			}
			$thetarget = quotemeta($thetarget);
			my $nlist = $4;
			@nicklist = split(",",$nlist);
			foreach my $nick (@nicklist) {
				$nick =~ s/:(.+?)$//;
				# :%a!b@c
				$nick =~ s/\s:%(.+?)$//; # remove bans
				$nick = quotemeta($nickhash{$nick});
				foreach my $mod (@modlist) {
					my $func = ("Modules::Scan::" . $mod . "::handle_join(\"$thenick\",\"$thetarget\")");
					eval $func;
				}
			}
		}

		if ($buffer =~ /^(.+?)\s(C|J)\s(.+?)\s\d+$/)
		{
			# Two types of join, a CREATE and a normal JOIN,
			# we treat them the same because we have
			# no need for memory allocation in perl
			print "Detected channel join\n" if $debug;
			my $thenick = $nickhash{$1};
			my $thetarget = $3;
			$thetarget = quotemeta($thetarget);
			$thenick = quotemeta($thenick);
			foreach my $mod (@modlist) {
				my $func = ("Modules::Scan::" . $mod . "::handle_join(\"$thenick\",\"$thetarget\")");
				eval $func;
			}
		}

		if ($buffer =~ /^(.+?)\sL\s(.+?)$/)
		{
			print "Detected channel part\n" if $debug;
			my $thenick = $nickhash{$1};
			my $thetarget = $2;
			$thenick = quotemeta($thenick);
			$thetarget = quotemeta($thetarget);
			foreach my $mod (@modlist) {
				my $func = ("Modules::Scan::" . $mod . "::handle_part(\"$thenick\",\"$thetarget\")");
				eval $func;
			}
		}

		# SERVER ircu.test.chatspike.net 1 1079214716 1079215442 J10 ABH]] + :ChatSpike developer team ircu test server
		if ($buffer =~ /^(SERVER|S)\s(.+?)\s(\d+)\s\d+\s\d+\s.+?\s(.+?)\s.+?\s:(.+?)$/)
		{
			$NETJOIN = 1;
			my $njservername = $2;
			my $hops = $3;
			my $njsid = substr($4,0,2);
			$serverids{$njsid} = $njservername;
			print "uplink ($njservername) is synching: ID=$njsid...\n";
			if ($hops == 1) { # this is our direct uplink to which we acknowledge end of a netburst, etc.
				$parentserver = $njsid;
			}
			$njtime = time+80;
		}

		if ($buffer =~ /^(.+?) EB/) # server telling us of end of netjoin
		{
			# we must acknowledge.
			my $theserver = $1;
			my $thesname = $serverids{$theserver};
			print "Server $thesname: end of netburst.\n";
			if ($acknowledged == 0) {
				my $now = time;
				print ("Introducing pseudoclient: $botnick...\n");
				# NICK [Brain] 1 1079188995 +aiow brain cpc2-mapp3-6-0-cust198.nott.cable.ntl.com hybrid.test.chatspike.net :There are no secrets except those that
				&rawirc("$servnumeric N $botnick 1 $now $botnick $domain +iok AAAAAA " . $servnumeric . "AAA :$botname");
				print ("Joining channel...\n");
				if ($mychants == 0) {
					$mychants = $now;
				}
				&rawirc("$servnumeric B $mychan $mychants +nst " . $servnumeric . "AAA:o");
			        print "Acknowledging end of my own netburst\n" if $debug;
			        &rawirc("$servnumeric EB"); # also tell the uplink that our own burst has ended
				&rawirc("$servnumeric EA");
				$acknowledged = 1;
			}
			$NETJOIN = 0;
		}

		if ($buffer =~ /^(.+?)\sO\s(.+?)\s:(.+?)$/)
		{
			$buffer = ":" . $nickhash{$1} . " NOTICE $2 :$3";
			&noticehandler($buffer);
		}

		if ($buffer =~ /^(.+?)\sG\s(.+)\s(.+)\s(.+)$/)
		{
			print "Ping? Pong!\n" if $debug;
			&rawirc("$servnumeric Z $2 $3");
		}

		elsif ($buffer =~ /^(.+?)\sP\s(.+?)\s:(.+?)$/) {
			$buffer = ":" . $nickhash{$1} . " PRIVMSG $2 :$3";
			&msghandler($buffer);
		}

		# ABAAA W DF :Defender

		elsif ($buffer =~ /^(.+?)\sW\s(.+?)\s:.+$/) {
			my $source = $1;
			# :bender.chatspike.net 320 [Brain] [Brain] :has whacked 33 virus drones
			&rawirc("$servnumeric 311 $source $botnick $botnick $domain * :$botname");
			&rawirc("$servnumeric 312 $source $botnick $servername :$serverdesc");
			&rawirc("$servnumeric 313 $source $botnick :is an IRC Operator");
			&rawirc("$servnumeric 317 $source $botnick 0 $START_TIME :seconds idle, signon time");
			&rawirc("$servnumeric 318 $source $botnick :End of /WHOIS list.");
		}
	}
	&reconnect;
}


# sig handler

sub shutdown {
	#print "SIGINT caught\n";
	&rawirc($servnumeric."AAA Q :Defender terminating");
	print("Disconnecting from irc server (SIGINT)\n");
	&rawirc("$servnumeric SQ $servnumeric :$quitmsg");
	# just for good measure, a 1 second delay
	sleep(1);
	close SH;
	exit;
}

sub handle_alarm
{
}

1;
