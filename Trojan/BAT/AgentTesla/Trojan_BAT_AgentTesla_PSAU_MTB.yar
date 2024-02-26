
rule Trojan_BAT_AgentTesla_PSAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 12 05 28 1b 90 01 03 07 09 18 6f 1c 90 01 03 06 28 1d 90 01 03 13 06 08 09 11 06 6f 1e 90 01 03 de 0c 11 05 2c 07 11 04 28 1f 90 01 03 dc 09 18 58 0d 09 07 6f 20 90 01 03 32 bd 08 6f 21 90 01 03 28 01 00 00 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}