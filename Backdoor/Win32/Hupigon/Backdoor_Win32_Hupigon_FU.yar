
rule Backdoor_Win32_Hupigon_FU{
	meta:
		description = "Backdoor:Win32/Hupigon.FU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 f2 62 88 10 40 ff } //01 00 
		$a_03_1 = {83 f8 7f 77 90 01 01 83 f8 14 72 90 00 } //01 00 
		$a_00_2 = {5c 73 79 73 6c 6f 67 2e 64 61 74 } //01 00  \syslog.dat
		$a_00_3 = {5f 6b 61 73 70 65 72 73 6b 79 } //00 00  _kaspersky
	condition:
		any of ($a_*)
 
}