
rule Trojan_BAT_AveMariaRat_MR_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_01_1 = {69 73 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //1 isVirtualMachine
		$a_01_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_3 = {6e 65 77 4d 75 74 65 78 } //1 newMutex
		$a_01_4 = {4f 00 5a 00 61 00 76 00 51 00 72 00 33 00 5a 00 61 00 32 00 41 00 34 00 76 00 65 00 63 00 67 00 36 00 68 00 36 00 70 00 49 00 67 00 3d 00 3d 00 } //1 OZavQr3Za2A4vecg6h6pIg==
		$a_01_5 = {44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 44 00 6c 00 6c 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 54 00 79 00 70 00 65 00 } //1 DynamicDllInvokeType
		$a_01_6 = {45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 EncryptionKey
		$a_01_7 = {66 67 73 64 61 61 61 61 61 61 61 61 61 61 61 67 73 64 67 73 } //1 fgsdaaaaaaaaaaagsdgs
		$a_01_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_9 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_10 = {53 6c 65 65 70 } //1 Sleep
		$a_01_11 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_12 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_13 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}