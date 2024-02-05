
rule Trojan_BAT_TeslaCrypt_VN_MTB{
	meta:
		description = "Trojan:BAT/TeslaCrypt.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 5d 91 61 d2 81 0e 00 00 01 00 07 17 13 90 01 01 20 90 01 04 20 90 01 04 20 90 01 04 61 20 90 01 04 40 90 01 03 00 20 90 01 03 00 13 90 01 01 20 90 01 04 58 00 58 0b 07 02 8e 69 fe 90 01 01 0d 09 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_TeslaCrypt_VN_MTB_2{
	meta:
		description = "Trojan:BAT/TeslaCrypt.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 20 00 2b 90 01 01 00 20 90 01 03 00 13 20 00 02 28 90 01 03 06 28 90 01 03 0a 13 21 73 90 01 03 06 13 22 19 8d 90 01 03 01 80 90 01 03 04 7e 90 01 03 04 16 7e 90 01 03 04 a2 7e 90 01 03 04 17 7e 90 01 03 04 a2 02 11 21 28 90 01 03 0a 7e 90 01 03 04 28 90 01 03 06 26 06 90 00 } //01 00 
		$a_03_1 = {01 0a 19 8d 90 01 03 01 25 16 72 90 01 03 70 a2 25 17 7e 90 01 03 04 a2 25 18 7e 90 01 03 04 a2 0a 06 28 90 01 03 0a 90 02 40 73 90 01 03 06 0b 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}