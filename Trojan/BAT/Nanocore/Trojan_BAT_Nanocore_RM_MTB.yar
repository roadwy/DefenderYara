
rule Trojan_BAT_Nanocore_RM_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
		$a_81_1 = {72 65 73 6f 75 72 63 65 43 75 6c 74 75 72 65 } //1 resourceCulture
		$a_81_2 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_4 = {67 65 74 5f 49 6e 6e 65 72 45 78 63 65 70 74 69 6f 6e } //1 get_InnerException
		$a_81_5 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //1 get_Computer
		$a_81_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_7 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_81_8 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //1 get_ExecutablePath
		$a_81_9 = {48 61 73 68 41 6c 67 6f 72 69 74 68 6d } //1 HashAlgorithm
		$a_81_10 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //1 ICryptoTransform
		$a_81_11 = {2a 2f 2a 47 2a 2f 2a 65 2a 2f 2a 74 2a 2f 2a 4d 2a 2f 2a 65 2a 2f 2a 74 2a 2f 2a 68 2a 2f 2a 6f 2a 2f 2a 64 } //1 */*G*/*e*/*t*/*M*/*e*/*t*/*h*/*o*/*d
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}