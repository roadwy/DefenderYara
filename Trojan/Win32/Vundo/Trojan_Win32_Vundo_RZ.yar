
rule Trojan_Win32_Vundo_RZ{
	meta:
		description = "Trojan:Win32/Vundo.RZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 b2 e9 38 53 08 75 10 83 7b 04 05 75 0a } //01 00 
		$a_03_1 = {b2 7c 8b ce e8 90 01 04 85 c0 7f 75 90 00 } //01 00 
		$a_01_2 = {33 c9 8a 0c 37 33 c1 88 04 37 46 eb } //00 00 
	condition:
		any of ($a_*)
 
}