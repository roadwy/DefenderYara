
rule Trojan_BAT_AgentTesla_NDP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 11 05 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 17 13 08 08 11 07 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 09 11 09 2d cb } //1
		$a_01_1 = {4f 30 4f 30 4f } //1 O0O0O
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}