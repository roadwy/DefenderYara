
rule Trojan_BAT_Redline_AR_MTB{
	meta:
		description = "Trojan:BAT/Redline.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 05 48 00 70 2b 04 2b 09 de 0d 28 90 01 03 06 2b f5 0a 2b f4 26 de e7 2b 01 2a 06 2b fc 90 00 } //01 00 
		$a_01_1 = {75 00 70 00 64 00 61 00 74 00 65 00 61 00 64 00 6f 00 62 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  updateadobe.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Redline_AR_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 01 28 27 00 00 0a 13 06 38 09 00 00 00 11 03 13 04 38 13 00 00 00 11 06 28 02 00 00 2b 28 03 00 00 2b 13 03 } //01 00 
		$a_01_1 = {76 00 69 00 72 00 74 00 6b 00 69 00 6f 00 73 00 6b 00 2e 00 65 00 78 00 65 00 } //00 00  virtkiosk.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Redline_AR_MTB_3{
	meta:
		description = "Trojan:BAT/Redline.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 08 16 13 09 2b 43 11 08 11 09 9a 0d 00 09 6f 90 01 03 0a 72 a3 00 00 70 6f 90 01 03 0a 16 fe 01 13 0a 11 0a 2d 1c 00 12 02 08 8e 69 17 58 28 90 01 03 2b 00 08 08 8e 69 17 59 09 6f 90 01 03 0a a2 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 fe 04 13 0a 11 0a 2d af 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}