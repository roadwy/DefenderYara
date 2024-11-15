
rule Trojan_Win64_Tedy_GA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {65 4a 75 56 42 78 67 6c 71 6a 42 6b 6e 56 48 59 61 59 64 61 75 70 75 63 6d 55 79 4b 46 4c 65 4a 75 56 42 78 67 6c 71 6a 42 6b 6e 56 48 59 61 59 64 61 75 70 75 63 6d 55 79 4b 46 4c } //8 eJuVBxglqjBknVHYaYdaupucmUyKFLeJuVBxglqjBknVHYaYdaupucmUyKFL
		$a_01_1 = {47 65 74 46 75 6c 6c 50 61 74 68 4e 61 6d 65 57 } //1 GetFullPathNameW
		$a_01_2 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 57 } //1 GetTempFileNameW
		$a_01_3 = {49 6e 69 74 69 61 6c 69 7a 65 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 } //1 InitializeSecurityDescriptor
		$a_01_4 = {43 72 79 70 74 43 41 54 41 64 6d 69 6e 43 61 6c 63 48 61 73 68 46 72 6f 6d 46 69 6c 65 48 61 6e 64 6c 65 } //1 CryptCATAdminCalcHashFromFileHandle
		$a_01_5 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //1 SetEndOfFile
		$a_01_6 = {55 6e 6b 6e 6f 77 6e 50 72 6f 64 75 63 74 } //1 UnknownProduct
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}