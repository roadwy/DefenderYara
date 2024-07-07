
rule Trojan_BAT_AgentTesla_MS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 17 19 8d 90 01 02 00 01 25 16 7e 90 01 02 00 04 a2 25 17 7e 90 01 02 00 04 a2 25 18 72 90 01 02 00 70 a2 a2 14 14 14 17 28 90 01 02 00 0a 26 1f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 16 06 07 08 09 28 90 01 0e a2 28 90 01 09 13 04 11 04 6f 90 01 04 16 9a 13 05 11 05 72 90 01 09 13 06 73 90 09 1c 00 d0 90 01 09 72 90 01 09 14 14 17 8d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}