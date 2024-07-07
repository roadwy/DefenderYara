
rule Trojan_BAT_AgentTesla_STJI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.STJI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 08 1f 16 5d 91 61 11 0b 59 20 00 01 00 00 5d d2 9c 00 11 08 17 58 13 08 11 08 11 04 09 17 58 5a fe 04 13 0d 11 0d 2d ae } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}