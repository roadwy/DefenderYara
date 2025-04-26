
rule Trojan_BAT_AgentTesla_EPT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 0d 06 02 08 18 6f ?? ?? ?? 0a 09 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 00 08 18 d6 0c } //1
		$a_01_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}