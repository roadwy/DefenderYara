
rule Trojan_Win32_Emotet_ZY{
	meta:
		description = "Trojan:Win32/Emotet.ZY,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //05 00 
		$a_01_1 = {0f be 03 89 } //05 00 
		$a_03_2 = {d3 e2 01 55 90 01 01 29 90 00 } //05 00 
		$a_01_3 = {80 3b 00 75 } //05 00 
		$a_01_4 = {0f b7 04 78 8b 34 86 03 f5 3b f3 } //00 00 
		$a_00_5 = {5d 04 00 00 a8 f2 04 80 5c 1f 00 00 a9 f2 04 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}