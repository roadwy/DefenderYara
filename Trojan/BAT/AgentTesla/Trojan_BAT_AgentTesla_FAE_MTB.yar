
rule Trojan_BAT_AgentTesla_FAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {0d 16 0a 2b 11 09 06 07 06 9a 1f 10 28 90 01 01 00 00 0a 9c 06 17 58 0a 06 07 8e 69 fe 04 13 06 11 06 2d e3 90 00 } //02 00 
		$a_01_1 = {72 61 64 61 72 73 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  radarsystem.Properties.Resources
	condition:
		any of ($a_*)
 
}