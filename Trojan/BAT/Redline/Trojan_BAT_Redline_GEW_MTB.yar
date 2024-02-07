
rule Trojan_BAT_Redline_GEW_MTB{
	meta:
		description = "Trojan:BAT/Redline.GEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 03 8e 69 5d 7e 90 01 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 19 58 18 59 03 8e 69 5d 91 59 20 03 01 00 00 58 18 59 17 59 20 90 01 04 5d d2 9c 08 1e 2c b3 17 58 15 2d 36 26 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {68 6b 67 66 73 66 64 66 66 64 68 66 68 64 64 72 66 61 68 67 68 64 64 73 73 68 63 66 } //00 00  hkgfsfdffdhfhddrfahghddsshcf
	condition:
		any of ($a_*)
 
}