
rule Trojan_BAT_AgentTesla_EJR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_01_1 = {2d 00 65 00 6e 00 63 00 20 00 59 00 77 00 42 00 74 00 41 00 47 00 51 00 41 00 49 00 41 00 41 00 76 00 41 00 47 00 4d 00 41 00 49 00 41 00 42 00 30 00 41 00 47 00 6b 00 41 00 62 00 51 00 42 00 6c 00 41 00 47 00 38 00 41 00 64 00 51 00 42 00 30 00 41 00 43 00 41 00 41 00 4d 00 67 00 41 00 77 00 41 00 41 00 3d 00 3d 00 } //01 00  -enc YwBtAGQAIAAvAGMAIAB0AGkAbQBlAG8AdQB0ACAAMgAwAA==
		$a_01_2 = {00 54 6f 41 72 72 61 79 73 00 } //01 00  吀䅯牲祡s
		$a_01_3 = {00 46 72 6f 6d 53 74 72 69 6e 67 00 } //01 00  䘀潲卭牴湩g
		$a_01_4 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_5 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}