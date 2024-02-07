
rule TrojanSpy_BAT_AgentTesla_NB_MTB{
	meta:
		description = "TrojanSpy:BAT/AgentTesla.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 72 49 01 00 70 28 90 01 03 06 7d 90 01 03 04 02 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {46 6f 72 4c 6f 6f 70 43 6f 6e 74 72 6f 6c } //01 00  ForLoopControl
		$a_01_3 = {67 58 63 6b 67 36 65 } //00 00  gXckg6e
	condition:
		any of ($a_*)
 
}