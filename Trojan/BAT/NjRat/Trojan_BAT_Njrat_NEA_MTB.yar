
rule Trojan_BAT_Njrat_NEA_MTB{
	meta:
		description = "Trojan:BAT/Njrat.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 70 00 67 00 74 00 7a 00 79 00 73 00 6b 00 72 00 67 00 76 00 61 00 76 00 69 00 73 00 77 00 } //01 00  Mpgtzyskrgvavisw
		$a_01_1 = {51 00 76 00 69 00 73 00 66 00 71 00 6b 00 66 00 2e 00 62 00 6d 00 70 00 } //01 00  Qvisfqkf.bmp
		$a_01_2 = {4f 75 79 70 61 6a 76 32 } //01 00  Ouypajv2
		$a_01_3 = {50 73 6e 6c 6a 78 71 62 2e 65 78 65 } //00 00  Psnljxqb.exe
	condition:
		any of ($a_*)
 
}