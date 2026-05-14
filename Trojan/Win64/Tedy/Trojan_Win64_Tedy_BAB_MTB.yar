
rule Trojan_Win64_Tedy_BAB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 40 2e 69 64 61 74 61 00 00 00 20 00 00 00 60 13 00 00 02 } //10
		$a_01_1 = {2e 72 73 72 63 00 00 00 00 3e 00 00 00 80 13 00 00 3e 00 00 00 b6 0f } //10
		$a_01_2 = {40 2e 74 68 65 6d 69 64 61 00 c0 76 00 00 c0 13 00 00 00 00 00 00 f4 0f } //10
		$a_01_3 = {2e 62 6f 6f 74 00 00 00 00 de 46 00 00 80 8a 00 00 de 46 00 00 f4 0f } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}
rule Trojan_Win64_Tedy_BAB_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 72 75 6e 53 69 6c 65 6e 74 } //1 main.runSilent
		$a_81_1 = {6d 61 69 6e 2e 78 64 } //1 main.xd
		$a_81_2 = {43 72 65 61 74 65 4b 65 79 45 78 57 } //1 CreateKeyExW
		$a_81_3 = {52 65 67 44 65 6c 65 74 65 56 61 6c 75 65 57 } //1 RegDeleteValueW
		$a_81_4 = {2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 65 78 65 } //1 -ExecutionPolicyexe
		$a_81_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_81_6 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //1 powershell.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}