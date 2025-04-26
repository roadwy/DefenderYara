
rule Trojan_BAT_AgentTesla_MBXG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 11 06 11 03 91 11 07 11 03 11 07 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 d2 9c } //1
		$a_01_1 = {43 32 34 54 47 4c 5f 30 30 30 30 30 35 33 31 2e 49 6d 70 6f 72 74 65 72 73 } //1 C24TGL_00000531.Importers
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}