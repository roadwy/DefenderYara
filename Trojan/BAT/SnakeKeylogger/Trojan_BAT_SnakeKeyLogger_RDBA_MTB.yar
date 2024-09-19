
rule Trojan_BAT_SnakeKeyLogger_RDBA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 2e 00 00 0a 6f 2f 00 00 0a 02 16 02 8e 69 6f 30 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_SnakeKeyLogger_RDBA_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f c0 00 00 0a 28 c1 00 00 0a 6f c2 00 00 0a 0b 07 6f c3 00 00 0a 16 9a 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}