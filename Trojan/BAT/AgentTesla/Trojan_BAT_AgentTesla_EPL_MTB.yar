
rule Trojan_BAT_AgentTesla_EPL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 02 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8 } //1
		$a_03_1 = {2b 0e 00 07 11 05 16 11 06 6f ?? ?? ?? 0a 00 00 09 11 05 16 11 04 6f ?? ?? ?? 0a 25 13 06 16 fe 03 13 08 11 08 2d db } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}