
rule Trojan_BAT_SnakeKeyLogger_WFB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.WFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 05 01 00 06 26 09 17 58 0d 09 1a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}