
rule Trojan_BAT_MassKeyLoader_MTB{
	meta:
		description = "Trojan:BAT/MassKeyLoader!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 17 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_1 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_01_2 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_3 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 NtUnmapViewOfSection
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {52 65 61 64 41 6c 6c 42 79 74 65 73 } //1 ReadAllBytes
		$a_01_6 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_01_7 = {41 73 73 65 6d 62 6c 79 42 75 69 6c 64 65 72 41 63 63 65 73 73 } //1 AssemblyBuilderAccess
		$a_01_8 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //1 CreateProcess
		$a_01_9 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_10 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 45 6d 69 74 } //1 System.Reflection.Emit
		$a_01_11 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_12 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //1 get_EntryPoint
		$a_01_13 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64GetThreadContext
		$a_01_14 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64SetThreadContext
		$a_01_15 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_16 = {4d 75 74 65 78 } //1 Mutex
		$a_01_17 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_01_18 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_19 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_20 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_21 = {47 65 74 52 75 6e 74 69 6d 65 44 69 72 65 63 74 6f 72 79 } //1 GetRuntimeDirectory
		$a_01_22 = {73 65 74 5f 49 6e 69 74 69 61 6c 44 69 72 65 63 74 6f 72 79 } //1 set_InitialDirectory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1) >=23
 
}