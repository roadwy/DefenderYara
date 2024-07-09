
rule Trojan_BAT_AgentTesla_ABFW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } //5
		$a_01_1 = {53 00 6d 00 61 00 72 00 74 00 5f 00 51 00 75 00 61 00 72 00 61 00 6e 00 74 00 69 00 6e 00 65 00 2e 00 52 00 65 00 73 00 44 00 53 00 44 00 53 00 } //1 Smart_Quarantine.ResDSDS
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}