
rule Trojan_BAT_AgentTesla_CL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
		$a_81_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_2 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_6 = {43 72 79 70 74 6f 67 72 61 70 68 79 } //1 Cryptography
		$a_81_7 = {67 65 74 5f 42 6c 6f 63 6b 53 69 7a 65 } //1 get_BlockSize
		$a_81_8 = {4c 6f 40 64 } //1 Lo@d
		$a_81_9 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_10 = {74 68 65 20 73 61 6d 65 20 61 67 65 20 61 73 } //1 the same age as
		$a_81_11 = {00 11 00 20 00 01 00 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}