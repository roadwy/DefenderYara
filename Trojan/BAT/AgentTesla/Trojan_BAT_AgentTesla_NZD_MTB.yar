
rule Trojan_BAT_AgentTesla_NZD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 09 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a } //1
		$a_03_1 = {72 8b 01 00 70 72 8f 01 00 70 6f ?? ?? ?? 0a 17 ?? ?? ?? ?? ?? 25 16 1f 40 9d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}