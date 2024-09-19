
rule Trojan_BAT_XWorm_RDL_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 17 73 29 00 00 0a 13 04 11 04 06 16 06 8e 69 6f 2a 00 00 0a 09 6f 2b 00 00 0a 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}