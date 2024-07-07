
rule Trojan_BAT_AgentTesla_AMBN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 04 5d 13 19 11 06 11 05 5d 13 1a 11 06 17 58 11 04 5d 13 1b 07 11 19 91 13 1c 20 00 01 00 00 13 1d 11 1c 08 11 1a 91 61 07 11 1b 91 59 11 1d 58 11 1d 5d 13 1e 07 11 19 11 1e d2 9c 11 06 17 58 13 06 00 11 06 11 04 09 17 58 5a fe 04 13 1f 11 1f 2d a9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}