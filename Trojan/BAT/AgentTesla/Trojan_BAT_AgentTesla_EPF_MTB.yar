
rule Trojan_BAT_AgentTesla_EPF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 07 91 11 04 61 09 06 91 61 13 05 08 07 11 05 d2 9c 06 03 } //1
		$a_03_1 = {06 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 08 18 d6 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}