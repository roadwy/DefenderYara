
rule Trojan_Win32_Gozi_B_MTB{
	meta:
		description = "Trojan:Win32/Gozi.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 ca 58 55 00 00 0f b7 d1 0f b7 f2 81 c7 08 1a 03 01 2b f0 8b 44 24 18 83 ee 07 89 38 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_B_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 2b d7 83 c2 2e 89 15 90 01 04 3b da 72 31 8b c2 0f af f1 2b c1 83 c3 26 69 ca 30 7b 00 00 03 d8 90 00 } //01 00 
		$a_81_1 = {73 6c 65 65 70 2e 64 6c 6c } //01 00 
		$a_81_2 = {45 67 67 62 61 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}