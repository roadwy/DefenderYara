
rule Trojan_Win32_Nanocore_J_ibt{
	meta:
		description = "Trojan:Win32/Nanocore.J!ibt,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 36 00 43 00 32 00 34 00 42 00 46 00 35 00 2d 00 33 00 36 00 39 00 30 00 2d 00 34 00 39 00 38 00 32 00 } //01 00 
		$a_01_1 = {7a 00 69 00 70 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_2 = {78 da bc 7d 77 60 14 c5 f7 f8 de de dd ee d5 } //00 00 
	condition:
		any of ($a_*)
 
}