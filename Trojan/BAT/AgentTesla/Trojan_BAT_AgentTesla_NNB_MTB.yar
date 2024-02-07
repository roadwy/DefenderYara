
rule Trojan_BAT_AgentTesla_NNB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {a2 25 18 7e 00 3a 00 04 a2 25 19 17 8c 90 01 03 01 a2 13 01 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 33 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //00 00  WindowsFormsApp3.Form1.resources
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NNB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 16 fe 02 16 fe 01 0c 08 2c 1c 07 17 d6 0b 06 72 90 01 03 70 28 90 01 03 0a 8c 90 01 03 01 6f 90 01 03 0a 00 2b d8 90 00 } //01 00 
		$a_01_1 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}