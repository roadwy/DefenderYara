
rule Trojan_Linux_StealthBot{
	meta:
		description = "Trojan:Linux/StealthBot,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 0f 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 74 68 42 6f 74 } //StealthBot  16
		$a_00_1 = {55 6e 61 62 6c 65 54 6f 43 72 65 61 74 65 4b 65 72 62 65 72 6f 73 43 72 65 64 65 6e 74 69 61 6c 73 } //4 UnableToCreateKerberosCredentials
		$a_00_2 = {4d 65 73 73 61 67 65 57 61 73 4e 6f 74 45 6e 63 72 79 70 74 65 64 57 69 74 68 54 68 65 52 65 71 75 69 72 65 64 45 6e 63 72 79 70 74 69 6e 67 54 6f 6b 65 6e } //4 MessageWasNotEncryptedWithTheRequiredEncryptingToken
		$a_00_3 = {43 61 6e 6e 6f 74 50 65 72 66 6f 72 6d 53 34 55 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4f 6e 50 6c 61 74 66 6f 72 6d } //4 CannotPerformS4UImpersonationOnPlatform
		$a_00_4 = {43 72 65 61 74 65 44 65 72 69 76 65 64 4b 65 79 54 6f 6b 65 6e } //4 CreateDerivedKeyToken
		$a_00_5 = {55 73 65 72 4e 61 6d 65 50 61 73 73 77 6f 72 64 56 61 6c 69 64 61 74 69 6f 6e 4d 6f 64 65 } //4 UserNamePasswordValidationMode
		$a_00_6 = {50 72 6f 76 69 64 65 49 6d 70 6f 72 74 45 78 74 65 6e 73 69 6f 6e 73 57 69 74 68 43 6f 6e 74 65 78 74 49 6e 66 6f 72 6d 61 74 69 6f 6e } //4 ProvideImportExtensionsWithContextInformation
		$a_00_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //4 CreateDecryptor
		$a_00_8 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //4 CreateEncryptor
		$a_00_9 = {50 6f 70 75 6c 61 74 65 38 33 46 69 6c 65 4e 61 6d 65 46 72 6f 6d 52 61 6e 64 6f 6d 42 79 74 65 73 } //4 Populate83FileNameFromRandomBytes
		$a_00_10 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 20 00 } //2 Virtual 
		$a_00_11 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 41 00 20 00 } //2 ResourceA 
		$a_00_12 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
		$a_00_13 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //1 Process32Next
		$a_00_14 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 ZwUnmapViewOfSection
	condition:
		((#a_80_0  & 1)*16+(#a_00_1  & 1)*4+(#a_00_2  & 1)*4+(#a_00_3  & 1)*4+(#a_00_4  & 1)*4+(#a_00_5  & 1)*4+(#a_00_6  & 1)*4+(#a_00_7  & 1)*4+(#a_00_8  & 1)*4+(#a_00_9  & 1)*4+(#a_00_10  & 1)*2+(#a_00_11  & 1)*2+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1) >=40
 
}