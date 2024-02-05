
rule Trojan_Win32_Miuref_I{
	meta:
		description = "Trojan:Win32/Miuref.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 ec 2c 8b 07 0f b7 48 14 83 65 f8 00 } //01 00 
		$a_01_1 = {8b d3 85 d2 75 15 f6 c1 40 74 05 8b } //01 00 
		$a_01_2 = {c1 ea 1d 83 e2 01 8b d9 c1 eb } //01 00 
		$a_01_3 = {73 7a 53 56 8d 71 24 8b 0e 8b d1 } //00 00 
	condition:
		any of ($a_*)
 
}