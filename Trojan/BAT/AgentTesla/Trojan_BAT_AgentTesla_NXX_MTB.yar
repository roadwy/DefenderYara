
rule Trojan_BAT_AgentTesla_NXX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00 00 11 64 00 78 00 66 00 68 00 74 00 79 00 79 00 37 00 00 0f 64 00 67 00 64 00 68 00 53 00 44 00 46 } //2
		$a_81_1 = {78 63 76 63 78 } //2 xcvcx
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NXX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {34 38 6d 43 4f 42 6b 50 54 4d 57 47 68 4a 68 54 53 65 37 64 52 31 67 6d 6a 78 71 68 } //1 48mCOBkPTMWGhJhTSe7dR1gmjxqh
		$a_81_1 = {4d 4b 35 4b 47 58 6f 36 6f 45 6b 43 51 52 42 52 42 62 76 2f 61 } //1 MK5KGXo6oEkCQRBRBbv/a
		$a_81_2 = {77 68 44 79 4f 32 4e 54 6b 64 4c 37 2f 53 71 4b 65 76 4f 37 2b 69 72 6a 6f 55 79 35 } //1 whDyO2NTkdL7/SqKevO7+irjoUy5
		$a_81_3 = {34 74 70 49 75 71 71 46 5a 67 73 73 65 49 5a 4f 38 70 66 4b 67 6f 2f 32 50 53 61 } //1 4tpIuqqFZgsseIZO8pfKgo/2PSa
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}