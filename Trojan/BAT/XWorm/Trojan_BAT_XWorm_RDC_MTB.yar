
rule Trojan_BAT_XWorm_RDC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 0e 00 00 04 6f 7b 00 00 0a 02 16 02 8e 69 6f 7c 00 00 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}