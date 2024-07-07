
rule Trojan_BAT_XWorm_RDE_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 11 00 00 0a 0a 06 28 04 00 00 06 28 12 00 00 0a 0a 06 72 3f 00 00 70 28 12 00 00 0a 0a 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}