
rule Trojan_BAT_AgentTesla_EQL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 06 02 06 91 11 05 18 d6 18 da 61 11 04 07 19 d6 19 da 91 61 } //1
		$a_03_1 = {07 02 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 09 18 d6 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}