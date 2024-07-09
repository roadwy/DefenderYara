
rule Trojan_BAT_AgentTesla_ABTF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc } //4
		$a_01_1 = {50 00 72 00 69 00 73 00 63 00 69 00 6c 00 6c 00 61 00 5f 00 54 00 61 00 79 00 6c 00 6f 00 72 00 } //1 Priscilla_Taylor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}