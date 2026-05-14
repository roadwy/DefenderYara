
rule Trojan_BAT_ShellCodeRunner_GPSD_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.GPSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {63 61 63 68 65 64 53 68 65 6c 6c 63 6f 64 65 44 61 74 61 } //1 cachedShellcodeData
		$a_81_1 = {63 61 63 68 65 64 53 74 61 67 65 32 44 61 74 61 } //1 cachedStage2Data
		$a_81_2 = {4e 6f 69 73 65 48 74 74 70 4d 65 74 68 6f 64 } //1 NoiseHttpMethod
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_4 = {67 65 74 5f 54 69 63 6b 43 6f 75 6e 74 } //1 get_TickCount
		$a_81_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_81_6 = {65 6e 63 72 79 70 74 65 64 41 73 73 65 6d 62 6c 79 4a 73 6f 6e } //1 encryptedAssemblyJson
		$a_81_7 = {52 61 6e 64 6f 6d 4e 75 6d 62 65 72 47 65 6e 65 72 61 74 6f 72 } //1 RandomNumberGenerator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}