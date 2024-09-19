
rule Trojan_BAT_XWorm_RDK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 91 11 09 61 13 0b 11 07 17 58 08 58 08 5d 13 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}