
rule Trojan_BAT_AgentTesla_RPE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 93 28 13 00 00 0a 06 59 13 05 11 05 07 31 08 11 05 07 59 13 05 2b 0b 11 05 08 2f 06 11 05 07 58 13 05 09 11 04 11 05 28 15 00 00 0a 9d 11 04 17 58 13 04 11 04 09 8e 69 32 c3 09 73 16 00 00 0a 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}