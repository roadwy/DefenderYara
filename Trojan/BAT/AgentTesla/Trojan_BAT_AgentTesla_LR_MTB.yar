
rule Trojan_BAT_AgentTesla_LR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 36 00 00 5d 91 08 09 1f 16 5d 6f 90 01 03 0a 61 07 09 17 58 20 00 36 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d b3 90 00 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_3 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_4 = {53 00 54 00 44 00 53 00 50 00 61 00 63 00 6b 00 61 00 67 00 65 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //01 00  STDSPackageBrowser
		$a_01_5 = {45 00 35 00 5a 00 38 00 34 00 35 00 53 00 35 00 41 00 48 00 44 00 41 00 45 00 35 00 48 00 47 00 47 00 4f 00 34 00 48 00 35 00 31 00 } //00 00  E5Z845S5AHDAE5HGGO4H51
	condition:
		any of ($a_*)
 
}