
rule Trojan_BAT_SnakeKeyLogger_RDCF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 72 af 00 00 70 28 1d 00 00 06 72 e1 00 00 70 28 13 00 00 0a 28 1e 00 00 06 13 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}