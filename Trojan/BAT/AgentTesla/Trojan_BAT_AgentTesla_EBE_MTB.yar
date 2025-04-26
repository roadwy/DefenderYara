
rule Trojan_BAT_AgentTesla_EBE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? ?? ?? 06 9c } //1
		$a_03_1 = {06 02 08 23 00 00 00 00 00 00 10 40 28 ?? ?? ?? 06 b7 6f ?? ?? ?? 0a 23 00 00 00 00 00 00 70 40 28 ?? ?? ?? 0a b7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}