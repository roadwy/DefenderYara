
rule TrojanProxy_Win32_Horst_gen_E{
	meta:
		description = "TrojanProxy:Win32/Horst.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 52 65 6d 65 6d 62 65 72 20 74 68 69 73 20 61 6e 73 77 65 72 } //01 00  &Remember this answer
		$a_00_1 = {57 61 72 6e 69 6e 67 3a 20 43 6f 6d 70 6f 6e 65 6e 74 73 20 48 61 76 65 20 43 68 61 6e 67 65 64 } //01 00  Warning: Components Have Changed
		$a_00_2 = {46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 } //01 00  FirewallPolicy\StandardProfile\Authorized
		$a_00_3 = {25 79 25 6d 25 64 25 48 25 4d 25 53 2e 25 2e } //01 00  %y%m%d%H%M%S.%.
		$a_01_4 = {4b 41 56 50 65 72 73 6f 6e 61 6c 35 30 } //01 00  KAVPersonal50
		$a_01_5 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_00_6 = {50 65 72 73 6f 6e 61 6c 20 46 69 72 65 77 61 6c 6c } //00 00  Personal Firewall
	condition:
		any of ($a_*)
 
}