
rule Trojan_BAT_XWorm_AWM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 04 2b 21 06 09 8f 16 00 00 01 25 47 07 11 04 91 09 1b 5d 58 d2 61 d2 52 09 17 58 0d 11 04 17 58 08 5d 13 04 09 06 8e 69 32 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}