
rule Trojan_BAT_Heracles_ZAJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 02 9a 28 ?? 00 00 0a 0a 06 8e 69 8d ?? 00 00 01 0b 16 0c 2b 1b 07 ?? 06 08 91 7e ?? 00 00 04 08 7e 01 00 00 04 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 fe 04 13 04 11 04 2d d9 28 ?? 00 00 0a 07 6f ?? 00 00 0a 0d 2b 00 09 2a } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}