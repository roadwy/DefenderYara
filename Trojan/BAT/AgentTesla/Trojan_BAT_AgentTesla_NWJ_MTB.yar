
rule Trojan_BAT_AgentTesla_NWJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 1b 59 1c 58 0d 09 17 fe 04 13 0a 11 0a 2d c3 } //1
		$a_81_1 = {50 50 30 30 30 30 36 } //1 PP00006
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}