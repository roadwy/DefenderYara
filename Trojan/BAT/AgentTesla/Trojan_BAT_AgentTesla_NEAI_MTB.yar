
rule Trojan_BAT_AgentTesla_NEAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 06 11 08 9a 1f 10 28 fe 00 00 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de 28 ff 00 00 0a 07 6f 00 01 00 0a } //10
		$a_01_1 = {50 00 21 00 65 00 73 00 2e 00 57 00 68 00 21 00 74 00 65 00 } //5 P!es.Wh!te
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}