
rule Trojan_BAT_AgentTesla_ABFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 08 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 05 11 05 02 28 ?? ?? ?? 06 00 11 04 6f ?? ?? ?? 0a 10 00 02 13 06 de 0d 11 05 2c 08 11 05 6f ?? ?? ?? 0a 00 dc 11 06 2a } //4
		$a_01_1 = {76 00 57 00 49 00 57 00 6a 00 59 00 48 00 68 00 51 00 4a 00 55 00 48 00 55 00 43 00 } //1 vWIWjYHhQJUHUC
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}