
rule Ransom_Win32_BlackCat_ZZ{
	meta:
		description = "Ransom:Win32/BlackCat.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_01_1 = {8b 45 08 66 0f 6f 02 66 0f 38 00 00 66 0f 7f 01 } //0a 00 
		$a_03_2 = {68 c0 1f 00 00 68 90 01 04 90 02 07 50 e8 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 b1 7d 05 80 5c 31 00 00 b2 7d 05 80 00 00 01 00 } //2e 00 
	condition:
		any of ($a_*)
 
}