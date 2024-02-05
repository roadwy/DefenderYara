
rule Trojan_Win32_Wasalad_A_{
	meta:
		description = "Trojan:Win32/Wasalad.A!!Wasalad.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {ba 00 00 00 00 b9 00 00 00 00 b8 00 00 00 00 52 6a 01 51 ff d0 c3 } //0a 00 
		$a_03_1 = {68 58 02 00 00 ff 15 90 01 04 eb f3 90 00 } //0a 00 
		$a_01_2 = {0f 31 8d 0d d0 60 10 01 0b 01 c1 d0 02 05 ef be ad de 1b c2 89 01 13 01 03 01 d1 d0 89 01 c3 } //0a 00 
	condition:
		any of ($a_*)
 
}