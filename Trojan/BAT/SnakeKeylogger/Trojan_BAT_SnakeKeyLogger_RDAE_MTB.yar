
rule Trojan_BAT_SnakeKeyLogger_RDAE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 1f 00 00 0a 0c 02 7b 13 00 00 04 6f 20 00 00 0a 16 6a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}