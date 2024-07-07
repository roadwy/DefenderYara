
rule Trojan_BAT_Heracles_GMZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 08 28 90 01 03 06 8c 2c 00 00 01 28 90 01 03 0a 28 90 01 03 0a 0a 08 7e 3f 00 00 04 8e 69 17 59 2e 0c 06 72 2d 03 00 70 28 90 01 03 0a 0a 08 17 58 0c 08 7e 3f 00 00 04 8e 69 32 c2 90 00 } //10
		$a_01_1 = {48 69 70 69 73 5f 43 6f 6e 76 46 6f 72 6d 61 74 } //1 Hipis_ConvFormat
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}