
rule Trojan_BAT_XWorm_RDM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 28 02 00 00 06 6f 20 00 00 0a 13 04 12 04 28 21 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}