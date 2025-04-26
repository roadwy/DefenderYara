
rule Trojan_BAT_SnakeKeyLogger_RDBU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 73 20 05 00 0a 0c 08 11 04 17 73 24 05 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}