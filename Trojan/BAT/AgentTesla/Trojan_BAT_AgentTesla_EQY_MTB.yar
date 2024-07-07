
rule Trojan_BAT_AgentTesla_EQY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 00 48 00 34 00 35 00 47 00 4a 00 31 00 34 00 47 00 34 00 45 00 35 00 47 00 59 00 51 00 44 00 34 00 53 00 47 00 4f 00 38 00 37 00 } //10 GH45GJ14G4E5GYQD4SGO87
		$a_01_1 = {50 00 64 00 59 00 56 00 } //5 PdYV
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}