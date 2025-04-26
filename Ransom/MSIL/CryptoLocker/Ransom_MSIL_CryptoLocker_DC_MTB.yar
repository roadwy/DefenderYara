
rule Ransom_MSIL_CryptoLocker_DC_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {58 42 75 6e 64 6c 65 72 54 6c 73 48 65 6c 70 65 72 2e 70 64 62 } //1 XBundlerTlsHelper.pdb
		$a_81_1 = {47 68 6f 73 74 2e 65 78 65 } //1 Ghost.exe
		$a_81_2 = {54 68 65 6d 69 64 61 } //1 Themida
		$a_81_3 = {73 68 6f 77 69 6e 73 74 61 6e 63 65 } //1 showinstance
		$a_81_4 = {64 65 61 63 74 69 76 61 74 65 } //1 deactivate
		$a_81_5 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Ransom_MSIL_CryptoLocker_DC_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {65 72 61 77 6f 73 6e 61 72 2e 65 78 65 } //1 erawosnar.exe
		$a_81_1 = {65 72 61 77 6f 73 6e 61 72 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 erawosnar.g.resources
		$a_81_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //1 set_UseMachineKeyStore
		$a_81_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}