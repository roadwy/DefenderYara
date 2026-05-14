
rule Trojan_BAT_Androm_CR_MTB{
	meta:
		description = "Trojan:BAT/Androm.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 11 18 6f 0a 00 00 0a 38 b3 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}