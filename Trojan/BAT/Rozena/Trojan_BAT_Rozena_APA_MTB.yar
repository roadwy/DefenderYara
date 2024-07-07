
rule Trojan_BAT_Rozena_APA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.APA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 8d 18 00 00 01 0b 16 0c 2b 11 00 07 08 06 08 93 28 90 01 03 0a 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e5 90 00 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}