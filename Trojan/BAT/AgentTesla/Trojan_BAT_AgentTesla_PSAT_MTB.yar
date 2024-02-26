
rule Trojan_BAT_AgentTesla_PSAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 12 05 28 1c 90 01 03 08 06 18 6f 1d 90 01 03 11 04 28 1e 90 01 03 13 06 07 06 11 06 6f 1f 90 01 03 de 0b 11 05 2c 06 09 28 20 90 01 03 dc 06 18 58 0a 06 08 6f 21 90 01 03 32 bf 07 6f 22 90 01 03 28 01 00 00 2b 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}