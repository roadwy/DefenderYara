
rule Trojan_BAT_XWorm_BAQ_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 0e 11 04 8e 69 5d 91 11 0d 61 d2 13 0f 11 0c 11 0e 11 0a 11 0e 91 11 0f 61 d2 9c 11 0a 11 0e 91 11 0e 20 ff 00 00 00 5f d2 61 d2 13 0d 11 0e 17 58 13 0e 11 0e 11 0a 8e 69 32 c2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_XWorm_BAQ_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 11 10 11 10 1f 5a 61 1f 5a 61 d2 9c 09 11 10 11 10 66 66 d2 9c 11 04 11 10 11 10 1a 62 11 10 1a 63 60 d2 9c 11 10 17 58 13 10 11 10 20 00 01 00 00 fe 04 2d ca } //2
		$a_81_1 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}