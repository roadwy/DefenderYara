
rule Trojan_BAT_AgentTesla_ABDA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {16 0b 09 20 90 01 03 12 5a 20 90 01 03 a5 61 38 90 01 03 ff 00 06 07 02 07 18 5a 18 28 90 01 03 06 1f 10 28 90 01 03 06 9c 90 00 } //01 00 
		$a_01_1 = {50 61 72 72 6f 74 74 2e 52 65 64 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Parrott.Red.resources
		$a_01_2 = {50 00 61 00 72 00 72 00 6f 00 74 00 74 00 } //00 00  Parrott
	condition:
		any of ($a_*)
 
}