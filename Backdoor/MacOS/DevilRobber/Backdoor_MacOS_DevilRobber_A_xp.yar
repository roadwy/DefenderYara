
rule Backdoor_MacOS_DevilRobber_A_xp{
	meta:
		description = "Backdoor:MacOS/DevilRobber.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 6e 7a 69 70 20 62 69 6e 61 72 79 2e 7a 69 70 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c } //01 00  unzip binary.zip > /dev/null
		$a_01_1 = {64 5f 73 74 61 74 75 73 2e 63 66 67 } //01 00  d_status.cfg
		$a_01_2 = {2e 2f 64 5f 73 74 6f 70 2e 73 68 } //01 00  ./d_stop.sh
		$a_01_3 = {2e 2f 70 5f 73 74 61 72 74 2e 73 68 } //03 00  ./p_start.sh
		$a_01_4 = {38 00 01 00 3d 60 80 80 39 20 00 00 7c 09 03 a6 61 6b 80 81 7c 49 49 d6 38 42 00 17 7c 02 58 16 54 00 c9 fe 7c 42 02 14 7c 43 49 ae 39 29 00 01 42 00 ff e4 38 60 00 00 4e 80 00 20 } //00 00 
	condition:
		any of ($a_*)
 
}