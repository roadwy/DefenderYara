
rule Trojan_BAT_AgentTesla_MA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_00_0 = {01 57 95 a2 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 c3 00 00 00 1e 00 00 00 7f 02 00 00 04 04 00 00 8b 02 } //3
		$a_81_1 = {47 75 69 64 41 74 74 72 69 62 75 74 65 } //3 GuidAttribute
		$a_81_2 = {48 65 6c 70 4b 65 79 77 6f 72 64 41 74 74 72 69 62 75 74 65 } //3 HelpKeywordAttribute
		$a_81_3 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //3 GeneratedCodeAttribute
		$a_81_4 = {74 78 74 50 61 73 73 77 6f 72 64 } //3 txtPassword
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}
rule Trojan_BAT_AgentTesla_MA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 "
		
	strings :
		$a_00_0 = {07 00 00 00 04 00 00 00 0a 00 00 00 02 00 00 00 03 00 00 00 03 00 00 00 08 } //10
		$a_80_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 } //aR3nbf8dQp2feLmk31  3
		$a_80_2 = {6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //lSfgApatkdxsVcGcrktoFd  3
		$a_80_3 = {43 6f 70 79 54 6f } //CopyTo  3
		$a_80_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //GetExecutingAssembly  3
		$a_80_5 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //GetManifestResourceStream  3
		$a_80_6 = {47 65 74 42 79 74 65 73 } //GetBytes  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=28
 
}
rule Trojan_BAT_AgentTesla_MA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2b 00 00 00 06 00 00 00 06 00 00 00 10 } //3
		$a_81_1 = {53 79 73 74 65 6d 2e 43 6f 6d 70 6f 6e 65 6e 74 4d 6f 64 65 6c } //3 System.ComponentModel
		$a_81_2 = {43 6f 6e 74 69 6e 75 65 57 68 65 6e 41 6c 6c } //3 ContinueWhenAll
		$a_81_3 = {73 65 74 5f 41 75 74 6f 52 65 73 65 74 } //3 set_AutoReset
		$a_81_4 = {54 61 73 6b 46 61 63 74 6f 72 79 } //3 TaskFactory
		$a_81_5 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //3 EditorBrowsableState
		$a_81_6 = {32 34 30 33 32 2e 33 30 31 38 2e 30 2e 31 } //3 24032.3018.0.1
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_BAT_AgentTesla_MA_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0a 00 00 "
		
	strings :
		$a_01_0 = {57 95 a2 29 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 49 00 00 00 14 00 00 00 3b 00 00 00 56 } //10
		$a_01_1 = {67 65 74 5f 43 75 72 72 65 6e 74 54 68 72 65 61 64 } //1 get_CurrentThread
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_5 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_7 = {72 61 6e 67 65 44 65 63 6f 64 65 72 } //1 rangeDecoder
		$a_01_8 = {50 61 72 61 6d 65 74 65 72 69 7a 65 64 54 68 72 65 61 64 53 74 61 72 74 } //1 ParameterizedThreadStart
		$a_01_9 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=19
 
}
rule Trojan_BAT_AgentTesla_MA_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {64 64 61 33 34 37 38 62 2d 64 34 36 33 2d 34 33 39 31 2d 38 63 30 34 2d 65 63 63 65 62 37 39 31 66 62 66 35 } //1 dda3478b-d463-4391-8c04-ecceb791fbf5
		$a_01_1 = {44 69 73 63 6f 72 64 5f 53 68 75 74 64 6f 77 6e } //1 Discord_Shutdown
		$a_01_2 = {42 79 4d 79 6e 69 78 2e 78 79 7a } //1 ByMynix.xyz
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //1 DownloadFileAsync
		$a_01_4 = {44 69 73 63 6f 72 64 5f 55 70 64 61 74 65 50 72 65 73 65 6e 63 65 } //1 Discord_UpdatePresence
		$a_01_5 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_7 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_8 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_9 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_10 = {73 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_UseSystemPasswordChar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}