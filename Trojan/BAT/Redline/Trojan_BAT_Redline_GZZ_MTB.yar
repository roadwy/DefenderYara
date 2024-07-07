
rule Trojan_BAT_Redline_GZZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 11 07 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 08 02 11 06 8f 1c 00 00 01 25 71 1c 00 00 01 06 11 08 91 61 d2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Redline_GZZ_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 40 18 5b 06 11 40 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 11 40 18 58 13 40 11 40 06 6f 90 01 03 0a fe 04 13 41 11 41 2d d2 90 00 } //10
		$a_01_1 = {46 75 6e 6e 79 54 68 69 6e 67 41 62 6f 75 74 54 68 61 74 } //1 FunnyThingAboutThat
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_BAT_Redline_GZZ_MTB_3{
	meta:
		description = "Trojan:BAT/Redline.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 04 00 00 0a 0a 06 28 90 01 03 0a 03 50 6f 90 01 03 0a 6f 90 01 03 0a 0b 73 08 00 00 0a 0c 08 07 6f 90 01 03 0a 08 18 6f 0a 90 01 02 0a 08 6f 90 01 03 0a 02 50 16 02 50 8e 69 6f 90 01 03 0a 2a 90 00 } //10
		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}