
rule Trojan_Win32_Sefnit_J{
	meta:
		description = "Trojan:Win32/Sefnit.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 f8 01 40 00 80 } //01 00 
		$a_01_1 = {0f b6 8c 28 f4 fe ff ff } //01 00 
		$a_01_2 = {88 94 29 f4 fe ff ff } //01 00 
		$a_01_3 = {8b e5 5d ff 25 } //01 00 
		$a_01_4 = {c7 45 f0 70 14 3a 03 } //01 00 
		$a_01_5 = {c7 45 f0 40 92 89 d1 } //01 00 
		$a_01_6 = {c7 45 f0 b0 e7 d9 f5 } //01 00 
		$a_01_7 = {66 c7 45 f4 82 14 } //00 00 
	condition:
		any of ($a_*)
 
}