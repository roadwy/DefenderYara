
rule TrojanDropper_BAT_AgentTesla_NRK_MTB{
	meta:
		description = "TrojanDropper:BAT/AgentTesla.NRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 47 00 00 06 38 90 01 03 ff 11 0e 28 90 01 03 0a 25 26 13 11 11 2b 20 90 01 03 00 28 90 01 03 06 5a 20 90 01 03 00 28 90 01 03 06 61 38 90 01 03 ff 73 90 01 03 0a 7a 11 2b 20 90 01 03 00 28 90 01 03 06 5a 20 90 01 03 00 28 90 01 03 06 61 90 00 } //01 00 
		$a_01_1 = {59 54 48 4f 50 4e 42 59 54 } //01 00  YTHOPNBYT
		$a_01_2 = {50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6c 61 73 73 } //01 00  ProcessInformationClass
		$a_01_3 = {4d 4a 43 4b 56 4b 4c 55 49 4f 52 } //01 00  MJCKVKLUIOR
		$a_01_4 = {52 53 44 53 26 39 38 } //00 00  RSDS&98
	condition:
		any of ($a_*)
 
}