
rule Trojan_BAT_XWorm_JKT_MTB{
	meta:
		description = "Trojan:BAT/XWorm.JKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 09 6f 24 00 00 0a 6f 28 00 00 0a 11 04 16 11 04 8e 69 6f 29 00 00 0a 13 05 28 10 00 00 0a 11 05 6f 12 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}