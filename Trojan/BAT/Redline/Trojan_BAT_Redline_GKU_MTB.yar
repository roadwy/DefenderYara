
rule Trojan_BAT_Redline_GKU_MTB{
	meta:
		description = "Trojan:BAT/Redline.GKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e 90 01 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 17 58 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 1b 2d 36 26 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 b1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Redline_GKU_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.GKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {91 03 06 03 8e b7 8c 90 01 04 28 90 01 03 0a 28 90 01 03 0a 91 61 02 06 17 28 90 01 03 0a 18 28 90 01 03 0a 8c 90 01 04 28 90 01 03 0a 02 8e b7 8c 90 01 04 28 90 01 03 0a 28 90 01 03 0a 91 59 20 90 01 04 28 90 01 03 0a 18 28 90 01 03 0a 58 20 90 01 04 28 90 01 03 0a 18 28 90 01 03 0a 5d d2 9c 00 06 11 04 12 00 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}