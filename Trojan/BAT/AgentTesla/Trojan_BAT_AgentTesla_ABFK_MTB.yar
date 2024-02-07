
rule Trojan_BAT_AgentTesla_ABFK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 9a 1f 10 28 90 01 03 0a 9c 09 17 d6 0d 00 09 20 90 01 03 00 fe 04 13 05 11 05 2d e0 90 00 } //01 00 
		$a_01_1 = {50 00 72 00 61 00 63 00 74 00 69 00 63 00 61 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  Practica1.Resources
		$a_01_2 = {50 00 72 00 61 00 63 00 74 00 69 00 63 00 61 00 31 00 2e 00 52 00 65 00 73 00 32 00 31 00 } //00 00  Practica1.Res21
	condition:
		any of ($a_*)
 
}