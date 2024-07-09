
rule Trojan_BAT_AgentTesla_NPR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 91 06 11 07 06 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a b4 61 9c 11 07 17 d6 13 07 11 07 11 06 31 d1 } //1
		$a_01_1 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}