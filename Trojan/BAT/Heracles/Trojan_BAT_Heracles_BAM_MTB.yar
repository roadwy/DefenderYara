
rule Trojan_BAT_Heracles_BAM_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 09 08 09 91 1f 0d 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 09 17 58 0d 09 08 8e 69 32 e0 16 13 04 2b 11 08 11 04 08 11 04 91 07 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 32 e8 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}