
rule Trojan_BAT_XWorm_RDG_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 09 16 09 8e b7 6f ef 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}