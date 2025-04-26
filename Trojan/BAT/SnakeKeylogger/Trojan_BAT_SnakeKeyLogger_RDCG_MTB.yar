
rule Trojan_BAT_SnakeKeyLogger_RDCG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 11 06 74 04 00 00 1b 73 bd 00 00 0a 16 17 73 be 00 00 0a 13 09 1d 13 14 11 14 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}