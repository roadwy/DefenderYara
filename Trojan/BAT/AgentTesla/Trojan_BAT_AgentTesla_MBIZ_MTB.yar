
rule Trojan_BAT_AgentTesla_MBIZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 1c 11 0e 11 16 91 13 1d 11 14 11 1c 6f 90 01 01 00 00 0a 13 1e 02 11 0e 11 0d 28 90 01 01 00 00 06 13 1f 02 11 1d 11 1e 11 1f 28 90 01 01 00 00 06 13 20 11 0e 11 16 11 20 20 00 01 00 00 5d d2 9c 11 0d 17 59 13 0d 11 0d 16 fe 04 16 fe 01 13 21 11 21 2d a4 90 00 } //01 00 
		$a_01_1 = {71 75 65 73 74 69 6f 6e 73 47 65 6e 65 72 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //00 00  questionsGenerator.Properties.Resources.resource
	condition:
		any of ($a_*)
 
}