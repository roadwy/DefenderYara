
rule Trojan_BAT_AgentTesla_RT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_02_0 = {06 07 9a 0c 08 28 90 01 03 0a 0d 09 72 90 01 03 70 72 90 01 03 70 17 15 16 28 90 01 03 0a 0d 02 6f 90 01 03 06 6f 90 01 03 0a 09 6f 90 01 03 0a 90 00 } //5
		$a_81_1 = {58 4f 52 5f 44 65 63 72 79 70 74 } //1 XOR_Decrypt
		$a_81_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_02_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_RT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 74 61 72 20 41 64 6d 69 72 61 6c } //Star Admiral  1
		$a_80_1 = {24 36 64 32 64 61 61 30 37 2d 34 39 38 30 2d 34 63 34 66 2d 39 63 66 30 2d 66 33 38 31 63 63 35 33 36 64 63 38 } //$6d2daa07-4980-4c4f-9cf0-f381cc536dc8  10
		$a_80_2 = {42 61 72 62 61 72 61 } //Barbara  1
		$a_80_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //ToCharArray  1
		$a_80_4 = {50 72 69 65 6e } //Prien  1
		$a_80_5 = {47 65 74 54 79 70 65 } //GetType  1
		$a_80_6 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //  10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*10) >=25
 
}
rule Trojan_BAT_AgentTesla_RT_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_1 = {24 43 42 31 43 32 46 45 31 2d 45 45 46 37 2d 34 32 45 32 2d 39 45 33 42 2d 37 36 30 31 31 31 38 33 45 43 32 36 } //10 $CB1C2FE1-EEF7-42E2-9E3B-76011183EC26
		$a_81_2 = {42 61 64 64 5f 43 6c 69 63 6b } //1 Badd_Click
		$a_81_3 = {47 65 74 45 6e 63 6f 64 69 6e 67 } //1 GetEncoding
		$a_81_4 = {67 65 74 5f 46 69 6c 65 50 61 74 68 } //1 get_FilePath
		$a_81_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_6 = {67 65 74 5f 57 68 69 74 65 53 6d 6f 6b 65 } //1 get_WhiteSmoke
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}
rule Trojan_BAT_AgentTesla_RT_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 37 61 64 31 38 33 31 65 2d 31 34 34 38 2d 34 63 31 39 2d 61 38 63 35 2d 61 62 34 37 31 66 64 34 31 32 35 39 } //1 $7ad1831e-1448-4c19-a8c5-ab471fd41259
		$a_81_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_3 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 } //1 GetEnvironmentVariable
		$a_81_6 = {67 65 74 5f 43 6f 6e 74 72 6f 6c 73 } //1 get_Controls
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}