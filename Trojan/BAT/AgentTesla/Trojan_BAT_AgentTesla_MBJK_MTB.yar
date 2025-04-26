
rule Trojan_BAT_AgentTesla_MBJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 1f 02 11 10 11 0f 28 ?? 01 00 06 13 20 02 11 1e 11 1f 11 20 28 ?? 01 00 06 13 21 11 10 11 18 11 21 20 00 01 00 00 5d d2 9c 11 0f 17 59 13 0f 11 0f 16 fe 04 16 fe 01 13 22 11 22 2d a4 } //1
		$a_01_1 = {70 72 6f 6a 65 63 74 71 6c 74 73 73 2e 50 72 6f 70 65 72 74 69 65 } //1 projectqltss.Propertie
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}