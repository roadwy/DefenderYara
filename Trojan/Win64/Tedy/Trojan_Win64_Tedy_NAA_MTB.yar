
rule Trojan_Win64_Tedy_NAA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_81_0 = {4d 75 73 71 75 69 74 61 6f 5c 44 65 73 6b 74 6f 70 5c 42 52 5f 32 30 32 33 5c 4c 4f 41 44 5f 32 30 32 33 5c 44 4c 4c 2d 43 50 50 5c 44 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 44 2e 70 64 62 } //5 Musquitao\Desktop\BR_2023\LOAD_2023\DLL-CPP\D\x64\Release\D.pdb
		$a_81_1 = {5c 44 6f 63 75 6d 65 6e 74 73 } //1 \Documents
		$a_81_2 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_81_3 = {44 2e 64 6c 6c } //1 D.dll
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=8
 
}