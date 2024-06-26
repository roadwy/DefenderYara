
rule Trojan_Win32_Emotet_I{
	meta:
		description = "Trojan:Win32/Emotet.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 68 40 23 23 77 65 68 2e 50 64 62 } //01 00  wh@##weh.Pdb
		$a_00_1 = {52 53 44 53 } //01 00  RSDS
		$a_03_2 = {55 89 e5 50 b8 90 01 04 31 c9 89 c2 81 ea e8 03 00 00 0f 47 c8 89 c8 89 55 fc 83 c4 04 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_I_2{
	meta:
		description = "Trojan:Win32/Emotet.I,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 c1 4a 3b 0d 40 20 47 00 75 1b 8b 15 08 20 47 00 83 c2 21 2b 15 40 20 47 00 } //0a 00 
		$a_01_1 = {89 0d 04 20 47 00 8b 15 08 20 47 00 69 d2 bb e3 00 00 2b 15 38 20 47 00 } //0a 00 
		$a_01_2 = {8b 15 04 20 47 00 69 d2 bb e3 00 00 2b 15 40 20 47 00 } //00 00 
	condition:
		any of ($a_*)
 
}