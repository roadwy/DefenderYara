
rule Trojan_BAT_AgentTesla_MBEN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 02 18 d6 13 02 38 ?? 00 00 00 11 00 02 11 02 } //10
		$a_01_1 = {02 11 06 91 11 01 61 11 00 11 03 91 61 13 05 } //10
		$a_03_2 = {62 02 03 04 18 6f ?? 00 00 0a 1f 10 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10) >=30
 
}