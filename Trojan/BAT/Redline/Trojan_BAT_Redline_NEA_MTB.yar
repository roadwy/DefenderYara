
rule Trojan_BAT_Redline_NEA_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 2d 08 08 6f 42 00 00 0a 13 04 de 33 07 2b cc 73 47 00 00 0a 2b c8 73 48 00 00 0a 2b c3 0d 2b c2 08 2c 07 08 6f 43 00 00 0a 00 dc } //01 00 
		$a_01_1 = {4c 00 68 00 65 00 77 00 7a 00 67 00 76 00 62 00 6c 00 64 00 63 00 76 00 70 00 67 00 61 00 69 00 72 00 } //01 00  Lhewzgvbldcvpgair
		$a_01_2 = {52 00 65 00 6e 00 65 00 76 00 63 00 74 00 5f 00 5a 00 64 00 72 00 70 00 6b 00 70 00 71 00 7a 00 2e 00 62 00 6d 00 70 00 } //00 00  Renevct_Zdrpkpqz.bmp
	condition:
		any of ($a_*)
 
}