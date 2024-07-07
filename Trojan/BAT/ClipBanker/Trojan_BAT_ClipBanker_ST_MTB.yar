
rule Trojan_BAT_ClipBanker_ST_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {52 69 6a 6e 64 61 65 6c } //1 Rijndael
		$a_81_4 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_81_5 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_81_6 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_00_8 = {24 63 38 61 36 66 34 30 63 2d 66 63 39 38 2d 34 31 62 33 2d 62 39 62 34 2d 37 61 36 33 66 34 31 38 66 66 31 32 } //1 $c8a6f40c-fc98-41b3-b9b4-7a63f418ff12
		$a_81_9 = {53 74 72 69 6e 67 43 6f 6d 70 61 72 69 73 6f 6e } //1 StringComparison
		$a_81_10 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_11 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_81_12 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_81_13 = {50 61 73 73 77 6f 72 64 44 65 72 69 76 65 42 79 74 65 73 } //1 PasswordDeriveBytes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_00_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}