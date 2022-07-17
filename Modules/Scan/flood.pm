# $Id: flood.pm 861 2004-11-24 11:30:33Z brain $

package Modules::Scan::flood;

use strict;
use warnings;

my %chans;
my @lockchans;
my @locktime;
my $nextinterval = time+3;
my $threshold1 = 12;
my $threshold2 = 20;
my $threshold3 = 25;
my $locked = 0;
my $warned = 0;
my $logged = 0;
my $totaljoins = 0;
my $nexttalk = 0;
my $interval = 5;

sub stats
{
	main::message("Flood threshold (log to channel):\002 $threshold1\002");
	main::message("Flood threshold (send globops):  \002 $threshold2\002");
	main::message("Flood threshold (lock channel):  \002 $threshold3\002");
	main::message("Total channels locked:           \002 $locked\002");
	main::message("Total warnings given:            \002 $warned\002");
	main::message("Total floods logged:             \002 $logged\002");
	main::message(" ");
	main::message("\002Locked channels:\002");
	main::message(" ");
	my $totalchans = 0;
	foreach my $channel (%chans) {
		$totalchans++;
	}
	my $totallocked = 0;
	foreach my $locked (@lockchans) {
		$totallocked++;
		main::message("   $locked\n");
	}
	main::message(" ");
	main::message("Currently watching\002 $totalchans\002 channels, with a total of\002 $totaljoins\002 joins and parts");
	main::message("in the last\002 $interval\002 second interval.\002 $totallocked\002 channels are currently locked.");
}

sub handle_expire
{
	if (defined($locktime[0]))
	{
		if ((time > $locktime[0]) && (defined($locktime[0])) && ($locktime[0] ne ''))
		{
			main::mode($lockchans[0],"-iCKmc");
			main::message("\002" . $lockchans[0] . "\002 was unlocked (flood lock time expired)");
			my $crap1 = shift @lockchans;
			my $crap2 = shift @locktime;
		}
	}
}

sub islocked
{
	my $comp = $_[0];
	if (defined($locktime[0]))
	{
		foreach my $chan (@lockchans) {
			if ($comp eq $chan) {
				return 1;
			}
		}
	}
	return 0;
}

sub handle_topic
{
}


sub generic_handler
{
	if ($main::NETJOIN == 1) {
		return;
	}

	my ($nick,$channel) = @_;
	$channel = lc($channel);

	if ($channel !~ /^#/) {
		return;
	}

	$totaljoins++;

	if (time > $nextinterval)
	{
		$nextinterval = time+$interval;
		%chans = ();
		$totaljoins = 0;
		return;
	}

	if (defined($chans{$channel})) {
		if ($chans{$channel} eq '') {
			$chans{$channel} = 0;
		}
	}
	else {
		$chans{$channel} = 0;
	}

	$chans{$channel}++;
	if ($chans{$channel} > $threshold3)
	{
		if (!islocked($channel)) {
			main::mode($channel,"+CKmic");
			main::notice($channel,"Your channel has been joined/parted\002 " . $chans{$channel} . "\002 times in the last\002 $interval\002 seconds which constitutes a \002flood\002. As a countermasure the modes \002+CKmic\002 have been set to prevent more flooding. Please remove these commands when the situation has averted. These modes will be automatically reversed in\002 1\002 minute.");
			main::globops("ALERT! \002$channel\002 has been joined/parted " . $chans{$channel} . " times in the last $interval seconds and has been temporarily locked!");
			$chans{$channel} = 0;
			push @locktime, time+60;
			push @lockchans, $channel;
			$locked++;
		}
		return;
	}
	if ($chans{$channel} > $threshold2)
	{
		if (time > $nexttalk)
		{
			main::globops("ALERT! \002$channel\002 has been joined/parted " . $chans{$channel} . " times in the last $interval seconds, if it reaches $threshold3 joins and parts, it will be locked temporarily.");
			$warned++;
			$nexttalk = time+20;
		}
		return;
	}
	if ($chans{$channel} > $threshold1)
	{
		if (time > $nexttalk)
		{
			main::message("Channel \002$channel\002 has had " . $chans{$channel} . " joins/parts in the past\002 $interval\002 seconds, $threshold2 triggers oper alert.");
			$logged++;
			$nexttalk = time+20;
		}
		return;
	}
}

sub handle_join
{
	&generic_handler(@_);
	&handle_expire;
}

sub handle_part
{
	&generic_handler(@_);
	&handle_expire;
}


sub scan_user
{
	my ($ident,$host,$serv,$nick,$gecos,$print_always) = @_;
	&handle_expire;
}


sub handle_notice
{
	my ($nick,$ident,$host,$chan,$notice) = @_;
}


sub handle_mode
{
	my ($nick,$target,$params) = @_;
	&handle_expire;
}


sub handle_privmsg
{
        my ($nick,$ident,$host,$chan,$msg) = @_;
	&handle_expire;
}


sub init {

        if (!main::depends("core-v1","server")) {
                print "This module requires version 1.x of defender and a server link module to be loaded.\n";
                exit(0);
        }
        main::provides("flood");

	$threshold1 = $main::dataValues{'flood_log'};
	$threshold2 = $main::dataValues{'flood_globops'};
	$threshold3 = $main::dataValues{'flood_lock'};
	$interval = $main::dataValues{'flood_interval'};
	&handle_expire;
}

1;
