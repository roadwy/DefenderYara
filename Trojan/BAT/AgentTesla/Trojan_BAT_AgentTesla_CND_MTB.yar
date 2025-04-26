
rule Trojan_BAT_AgentTesla_CND_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 05 08 28 4a 00 00 06 13 07 09 28 4b 00 00 06 13 08 11 08 11 07 16 28 4c 00 00 06 13 09 } //5
		$a_01_1 = {50 61 73 73 47 65 6e } //1 PassGen
		$a_01_2 = {4d 75 74 65 78 } //1 Mutex
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}