
rule Trojan_BAT_AgentTesla_CXJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 13 08 16 13 09 11 08 12 09 28 ?? ?? ?? ?? 00 08 07 11 07 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 de 0d 11 09 2c 08 11 08 28 ?? ?? ?? ?? 00 dc 00 11 07 18 58 13 07 11 07 07 6f ?? ?? ?? ?? fe 04 13 0a 11 0a 2d b2 } //1
		$a_01_1 = {53 68 6f 7a 62 78 79 78 70 6f 6a 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Shozbxyxpoj.Properties
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}