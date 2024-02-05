
rule Trojan_Win32_Alureon_EW{
	meta:
		description = "Trojan:Win32/Alureon.EW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 46 14 8d 7c 30 18 8b 46 50 6a 40 } //01 00 
		$a_01_1 = {76 11 8b 44 24 04 03 c1 30 10 fe c2 41 3b 4c 24 08 72 ef } //01 00 
		$a_03_2 = {c6 45 f8 74 c6 45 f9 73 c6 45 fa 74 33 c0 88 90 01 08 00 01 00 00 90 00 } //01 00 
		$a_01_3 = {78 74 61 73 6b 73 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}