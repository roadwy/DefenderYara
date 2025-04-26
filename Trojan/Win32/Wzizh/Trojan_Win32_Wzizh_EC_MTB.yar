
rule Trojan_Win32_Wzizh_EC_MTB{
	meta:
		description = "Trojan:Win32/Wzizh.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {41 75 74 6f 52 75 6e } //1 AutoRun
		$a_81_1 = {66 69 6c 65 6e 61 6d 65 2e 64 6c 6c } //1 filename.dll
		$a_81_2 = {74 65 6d 70 6b 65 79 } //1 tempkey
		$a_81_3 = {52 75 6e 5f 46 72 6f 6d 5f 4d 65 6d 6f 72 79 } //1 Run_From_Memory
		$a_81_4 = {44 4c 4c 5f 49 6e 6a 65 63 74 69 6f 6e } //1 DLL_Injection
		$a_81_5 = {44 65 62 75 67 67 65 72 5f 49 64 65 6e 74 69 66 69 63 61 74 69 6f 6e } //1 Debugger_Identification
		$a_81_6 = {43 50 55 5f 49 64 65 6e 74 69 66 69 63 61 74 69 6f 6e } //1 CPU_Identification
		$a_81_7 = {44 65 63 6f 64 65 5f 42 61 73 65 36 34 } //1 Decode_Base64
		$a_81_8 = {44 65 6c 65 74 65 5f 46 69 6c 65 } //1 Delete_File
		$a_81_9 = {44 65 6c 65 74 65 5f 49 74 73 65 6c 66 } //1 Delete_Itself
		$a_81_10 = {4c 6f 61 64 5f 46 72 6f 6d 5f 46 69 6c 65 } //1 Load_From_File
		$a_81_11 = {53 74 72 69 6e 67 5f 58 4f 52 } //1 String_XOR
		$a_81_12 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 CurrentVersion\Run
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}