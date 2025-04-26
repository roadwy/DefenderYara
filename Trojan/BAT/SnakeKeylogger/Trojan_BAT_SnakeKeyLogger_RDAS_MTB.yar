
rule Trojan_BAT_SnakeKeyLogger_RDAS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 8e 69 6f b0 00 00 0a 13 0a 11 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}