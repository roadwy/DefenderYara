
rule Trojan_BAT_AgentTesla_GH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 1f 6e 7e 90 01 03 04 1f 76 7e 90 01 03 04 1f 76 91 7e 90 01 03 04 1f 1c 91 61 1b 5f 9c 2a 90 00 } //01 00 
		$a_02_1 = {ff 1f 4d 7e 90 01 03 04 1f 3b 7e 90 01 03 04 1f 3b 94 7e 90 01 03 04 20 90 01 03 00 94 5a 20 90 01 03 00 5f 9e 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_GH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 6f 7a 65 6e 62 61 79 6e 2e 46 6f 72 6d 90 01 01 2e 72 65 73 6f 75 72 63 65 73 90 00 } //01 00 
		$a_03_1 = {70 72 6f 6a 65 74 6f 72 2e 46 6f 72 6d 90 01 01 2e 72 65 73 6f 75 72 63 65 73 90 00 } //01 00 
		$a_81_2 = {46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Form1.resources
		$a_81_3 = {46 6f 72 6d 32 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Form2.resources
		$a_81_4 = {46 6f 72 6d 33 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Form3.resources
		$a_03_5 = {46 6f 72 6d 90 01 01 5f 4c 6f 61 64 90 00 } //01 00 
		$a_81_6 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_81_7 = {67 65 74 5f 4c 65 6e 67 74 68 } //01 00  get_Length
		$a_81_8 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_9 = {43 6f 6e 76 65 72 74 } //00 00  Convert
	condition:
		any of ($a_*)
 
}