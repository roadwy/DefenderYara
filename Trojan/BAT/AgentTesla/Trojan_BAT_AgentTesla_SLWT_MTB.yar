
rule Trojan_BAT_AgentTesla_SLWT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SLWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 20 8d 0c 00 00 01 0d 28 14 00 00 0a 09 6f 15 00 00 0a 25 09 6f 08 00 00 06 13 04 25 11 04 6f 0a 00 00 06 13 05 11 04 08 6f 0c 00 00 06 13 06 28 8e 00 00 06 13 07 28 65 00 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}