
rule Ransom_Win32_Filecoder_GH_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {56 6f 6c 61 74 69 6c 65 41 74 74 72 69 62 75 74 65 } //1 VolatileAttribute
		$a_81_1 = {4c 6f 61 64 46 72 6f 6d 53 74 72 65 61 6d } //1 LoadFromStream
		$a_81_2 = {53 61 76 65 54 6f 46 69 6c 65 } //1 SaveToFile
		$a_81_3 = {45 6e 63 72 79 70 74 5f 38 62 69 74 } //1 Encrypt_8bit
		$a_81_4 = {44 65 63 72 79 70 74 5f 42 6c 6f 63 6b } //1 Decrypt_Block
		$a_81_5 = {49 42 6c 6f 63 6b 43 68 61 69 6e 69 6e 67 4d 6f 64 65 6c 20 5b 4d } //1 IBlockChainingModel [M
		$a_81_6 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_81_7 = {55 73 65 72 6e 61 6d 65 } //1 Username
		$a_81_8 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //1 ShellExecuteW
		$a_81_9 = {49 64 43 75 73 74 6f 6d 54 43 50 53 65 72 76 65 72 } //1 IdCustomTCPServer
		$a_81_10 = {44 43 50 74 77 6f 66 69 73 68 5f 4c 42 33 4d 6f 64 69 66 69 65 64 } //1 DCPtwofish_LB3Modified
		$a_81_11 = {21 51 55 45 52 59 5f 43 52 45 44 45 4e 54 49 41 4c 53 5f 41 54 54 52 49 42 55 54 45 53 5f 46 4e 5f 57 59 } //1 !QUERY_CREDENTIALS_ATTRIBUTES_FN_WY
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}