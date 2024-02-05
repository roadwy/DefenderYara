
rule Trojan_Win32_Ogpha_B{
	meta:
		description = "Trojan:Win32/Ogpha.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 72 64 2f 66 78 74 6f 31 2e 70 68 70 } //01 00 
		$a_01_1 = {38 39 2e 31 34 39 2e 32 32 36 2e 35 34 00 } //01 00 
		$a_01_2 = {66 36 32 36 33 34 31 39 63 31 63 66 64 63 30 64 36 65 62 33 62 38 64 35 37 36 64 63 64 32 66 32 00 } //02 00 
		$a_01_3 = {83 7d fc 05 7d 31 83 7d f8 05 7d 2b } //00 00 
	condition:
		any of ($a_*)
 
}