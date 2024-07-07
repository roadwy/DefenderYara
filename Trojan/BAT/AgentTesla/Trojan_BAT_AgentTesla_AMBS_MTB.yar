
rule Trojan_BAT_AgentTesla_AMBS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 04 5d 13 08 11 05 1f 16 5d 13 09 11 05 17 58 11 04 5d 13 0a 07 11 08 91 13 0b 20 00 01 00 00 13 0c 11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0e 11 0e 2d a9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}