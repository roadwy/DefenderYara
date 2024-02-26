
rule Trojan_BAT_AgentTesla_MBEM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 8e 69 18 5a 1f 16 58 0c 2b 4b 08 07 8e 69 5d 13 05 08 11 04 6f 90 01 01 00 00 0a 5d 13 09 07 11 05 91 13 0a 11 04 11 09 6f 90 01 01 00 00 0a 13 0b 02 07 08 28 90 01 01 00 00 06 13 0c 02 11 0a 11 0b 11 0c 28 90 01 01 00 00 06 13 0d 07 11 05 02 11 0d 90 00 } //01 00 
		$a_01_1 = {41 70 70 43 6f 6e 6e 65 63 74 44 61 74 61 2e 50 72 6f 70 65 72 74 69 65 } //00 00  AppConnectData.Propertie
	condition:
		any of ($a_*)
 
}