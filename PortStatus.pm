# /etc/perl

use strict;
use warnings;

sub Check_Port{
	my $syn, my $fin, my $rst, my $psh, my $urg, my $ack, my $mode, my $dst_port, my $flag_option;
	($syn, $fin, $rst, $psh, $urg, $ack, $mode, $dst_port, $flag_option)=@_;

	#for 'mode option'
	if($mode eq "Ts" or $mode eq "Tss"){
		if($syn!=0 and $ack=!0){
			Alert_Open($dst_port);
		}
		elsif($rst!=0 and $ack!=0){
			Alert_Close($dst_port);
		}
	}
	elsif($mode eq "Tsf"){
		if($rst!=0){
			Alert_Close($dst_port);
		}
	}
	elsif($mode eq "Tsx"){
		if($rst!=0){
			Alert_Close($dst_port);
		}
	}
	elsif($mode eq "Tsn"){
		if($rst!=0){
			Alert_Close($dst_port);
		}
	}
	elsif($mode eq "A"){
		if($rst!=0){
			Alert_NFilter($dst_port);
		}
	}

	#for 'flag option'
	if($flag_option eq "S" or $flag_option eq "s"){
		if($syn!=0 and $ack=!0){
			Alert_Open($dst_port);
		}
		elsif($rst!=0 and $ack!=0){
			Alert_Close($dst_port);
		}
	}
	elsif($flag_option eq "F" or $flag_option eq "f"){
		if($rst!=0){
			Alert_Close($dst_port);
		}
	}
	elsif($flag_option=~/F/i){
		if($flag_option=~/P/i){
			if($flag_option=~/U/i){
				if($rst!=0){
					Alert_Close($dst_port);
				}
			}
		}
	}
	elsif($flag_option eq "" and $mode eq ""){
		if($rst!=0){
			Alert_Close($dst_port);
		}
	}
	elsif($flag_option eq "A" or $flag_option eq "a"){
		if($rst!=0){
			Alert_NFilter($dst_port);
		}
	}
}

sub Alert_Open{
	my $is;
	($is)=@_;
	print "[RESULT] $is port is opened.\n";
}

sub Alert_Close{
	my $is;
	($is)=@_;
	print "[RESULT] $is port is closed.\n";
}

sub Alert_NFilter{
	my $is;
	($is)=@_;
	print "[RESULT] $is port is not filtered.\n";
}

1;
