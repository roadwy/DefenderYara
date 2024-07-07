
rule Trojan_BAT_AgentTesla_DL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 13 0c 07 11 09 11 0c 08 11 08 1f 16 5d 91 61 11 0b 59 20 00 01 00 00 5d d2 9c 00 11 08 17 58 13 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_DL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 09 00 00 "
		
	strings :
		$a_81_0 = {24 39 63 34 65 61 62 39 30 2d 34 66 33 39 2d 34 31 31 64 2d 38 35 64 61 2d 38 62 30 30 65 31 32 39 31 62 36 65 } //20 $9c4eab90-4f39-411d-85da-8b00e1291b6e
		$a_81_1 = {24 37 38 37 34 30 30 61 36 2d 61 32 65 36 2d 34 37 33 61 2d 38 61 32 32 2d 37 66 39 65 38 66 31 63 35 33 66 64 } //20 $787400a6-a2e6-473a-8a22-7f9e8f1c53fd
		$a_81_2 = {24 65 39 36 38 65 65 62 37 2d 61 36 39 36 2d 34 66 38 35 2d 39 65 39 33 2d 37 37 33 63 64 32 32 66 30 31 35 34 } //20 $e968eeb7-a696-4f85-9e93-773cd22f0154
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_4 = {4d 65 6e 74 51 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 MentQ.Properties.Resources
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {54 69 74 6c 65 45 64 69 74 6f 72 2e 54 69 74 6c 65 4c 69 73 74 2e 72 65 73 6f 75 72 63 65 73 } //1 TitleEditor.TitleList.resources
		$a_81_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_8 = {49 54 50 5f 52 4d 53 53 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 ITP_RMSS.Properties.Resources
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=23
 
}