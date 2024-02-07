
rule Trojan_Win32_Woripecs_gen_A{
	meta:
		description = "Trojan:Win32/Woripecs.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 0d 00 00 04 00 "
		
	strings :
		$a_03_0 = {83 fa 50 74 38 6a 01 8d 4d e4 e8 90 01 04 0f be 00 83 f8 4f 74 26 6a 02 8d 4d e4 e8 90 01 04 0f be 08 83 f9 53 74 14 6a 03 8d 4d e4 e8 90 01 04 0f be 10 83 fa 54 74 02 90 00 } //02 00 
		$a_01_1 = {2f 69 73 75 70 2e 70 68 70 } //02 00  /isup.php
		$a_01_2 = {2f 73 65 74 76 61 72 2e 70 68 70 3f 6b 65 79 3d } //02 00  /setvar.php?key=
		$a_01_3 = {2f 68 6f 73 74 6e 61 6d 65 2e 70 68 70 3f 68 6f 73 74 3d } //02 00  /hostname.php?host=
		$a_01_4 = {2f 63 68 65 63 6b 70 6f 72 74 2e 70 68 70 3f 70 6f 72 74 3d 25 64 26 } //01 00  /checkport.php?port=%d&
		$a_01_5 = {44 41 54 41 4b 45 59 3a } //01 00  DATAKEY:
		$a_01_6 = {54 48 45 46 4f 4f 54 45 52 46 49 4c 45 3a } //01 00  THEFOOTERFILE:
		$a_01_7 = {25 73 74 65 61 6c 5f 6c 6f 67 69 6e 25 } //01 00  %steal_login%
		$a_01_8 = {25 6e 6f 5f 61 75 74 6f 5f 68 6f 73 74 73 25 } //01 00  %no_auto_hosts%
		$a_01_9 = {25 73 65 6c 66 5f 63 68 65 63 6b 5f 70 61 73 73 65 64 25 } //01 00  %self_check_passed%
		$a_01_10 = {25 65 73 63 72 6f 77 5f 69 70 25 } //01 00  %escrow_ip%
		$a_01_11 = {25 61 75 74 6f 70 69 6e 67 25 } //01 00  %autoping%
		$a_01_12 = {25 64 6f 5f 63 70 75 69 6e 66 6f 25 } //00 00  %do_cpuinfo%
	condition:
		any of ($a_*)
 
}