
rule Trojan_BAT_AgentTesla_NP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 00 0f 00 28 ?? 00 00 06 25 26 0f 01 28 ?? 00 00 06 25 26 d0 01 00 00 1b 28 ?? 00 00 0a 25 26 28 ?? 00 00 0a 25 26 a5 01 00 00 1b 0a 38 00 00 00 00 06 2a } //1
		$a_01_1 = {57 b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 } //1
		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //1 GetDelegateForFunctionPointer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_NP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 0a 06 28 ?? ?? ?? 0a 25 26 0b 28 ?? ?? ?? 0a 25 26 07 16 07 8e 69 6f ?? ?? ?? 0a 25 26 0a 09 20 ?? ?? ?? 5d 5a 20 ?? ?? ?? 3e 61 2b ad } //10
		$a_01_1 = {54 00 6b 00 4a 00 45 00 55 00 30 00 70 00 49 00 55 00 30 00 52 00 4b 00 53 00 46 00 4e 00 45 00 4e 00 7a 00 67 00 7a 00 4e 00 43 00 51 00 3d } //1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}
rule Trojan_BAT_AgentTesla_NP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 0b 00 00 "
		
	strings :
		$a_81_0 = {4d 65 64 69 63 61 6c 5f 4c 61 62 6f 72 61 74 6f 72 79 2e 52 65 73 75 6c 74 5f 31 2e 72 65 73 6f 75 72 63 65 73 } //7 Medical_Laboratory.Result_1.resources
		$a_81_1 = {67 65 74 5f 46 54 31 } //7 get_FT1
		$a_81_2 = {24 38 32 63 64 31 62 63 66 2d 31 64 64 37 2d 34 62 61 39 2d 62 65 38 37 2d 36 32 35 62 62 66 62 64 39 36 61 32 } //7 $82cd1bcf-1dd7-4ba9-be87-625bbfbd96a2
		$a_81_3 = {50 61 73 73 77 6f 72 64 3d 31 32 33 34 35 36 37 38 } //7 Password=12345678
		$a_81_4 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_7 = {50 61 72 61 6d 65 74 65 72 69 7a 65 64 54 68 72 65 61 64 53 74 61 72 74 } //1 ParameterizedThreadStart
		$a_81_8 = {46 61 69 6c 46 61 73 74 } //1 FailFast
		$a_81_9 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //1 get_IsAttached
		$a_81_10 = {5f 45 4e 41 42 4c 45 5f 50 52 4f 46 49 4c 49 4e 47 } //1 _ENABLE_PROFILING
	condition:
		((#a_81_0  & 1)*7+(#a_81_1  & 1)*7+(#a_81_2  & 1)*7+(#a_81_3  & 1)*7+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=32
 
}