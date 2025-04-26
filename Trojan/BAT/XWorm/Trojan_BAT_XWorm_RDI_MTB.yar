
rule Trojan_BAT_XWorm_RDI_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 07 16 09 a2 07 17 08 6f 3c 00 00 0a a2 07 18 07 16 9a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}