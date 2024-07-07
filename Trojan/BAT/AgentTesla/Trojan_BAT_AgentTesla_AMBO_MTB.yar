
rule Trojan_BAT_AgentTesla_AMBO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 04 5d 13 08 11 07 1f 16 5d 13 09 11 07 17 58 11 04 5d 13 0a 07 11 08 91 13 0b 20 00 01 00 00 13 0c 11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 00 11 07 17 58 13 07 11 07 11 04 09 17 58 5a fe 04 13 0e 11 0e 2d a9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}