
rule Backdoor_BAT_Remcos_ZSA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ZSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0e 00 00 "
		
	strings :
		$a_01_0 = {65 64 62 62 32 65 30 39 2d 36 38 30 63 2d 34 66 34 37 2d 62 37 63 37 2d 31 35 61 36 35 39 35 66 39 61 65 62 } //10 edbb2e09-680c-4f47-b7c7-15a6595f9aeb
		$a_01_1 = {45 71 75 61 6c 73 } //1 Equals
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {47 65 74 46 72 61 6d 65 } //1 GetFrame
		$a_01_4 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_7 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_8 = {47 65 74 43 61 6c 6c 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetCallingAssembly
		$a_01_9 = {41 70 70 65 6e 64 } //1 Append
		$a_01_10 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_11 = {47 65 74 4e 61 6d 65 } //1 GetName
		$a_01_12 = {4d 6f 64 65 } //1 Mode
		$a_01_13 = {50 61 64 64 69 6e 67 } //1 Padding
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=23
 
}