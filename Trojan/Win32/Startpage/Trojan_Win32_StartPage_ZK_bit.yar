
rule Trojan_Win32_StartPage_ZK_bit{
	meta:
		description = "Trojan:Win32/StartPage.ZK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 00 67 00 32 00 33 00 34 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_01_1 = {53 00 65 00 63 00 6f 00 6e 00 64 00 61 00 72 00 79 00 20 00 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 73 00 } //01 00 
		$a_01_2 = {77 00 7a 00 6a 00 75 00 6a 00 75 00 6d 00 61 00 6f 00 5f 00 63 00 62 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}