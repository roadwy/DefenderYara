
rule Trojan_BAT_XWorm_BA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 07 91 13 06 11 06 09 11 04 6f 27 00 00 0a 28 28 00 00 0a 61 b4 28 29 00 00 0a 13 05 06 11 05 6f 2a 00 00 0a 11 04 17 d6 09 6f 2b 00 00 0a 5d 13 04 11 07 17 d6 13 07 11 07 11 08 8e b7 32 be } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}