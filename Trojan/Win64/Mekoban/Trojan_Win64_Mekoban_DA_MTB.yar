
rule Trojan_Win64_Mekoban_DA_MTB{
	meta:
		description = "Trojan:Win64/Mekoban.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 4d 75 73 71 75 69 74 61 6f } //20 C:\Users\Musquitao
		$a_81_1 = {4c 4f 41 44 5f 45 58 45 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4c 4f 41 44 5f 45 58 45 2e 70 64 62 } //1 LOAD_EXE\x64\Release\LOAD_EXE.pdb
		$a_81_2 = {41 64 6f 62 65 20 44 6f 77 6e 6c 6f 61 64 20 4d 61 6e 61 67 65 72 } //10 Adobe Download Manager
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*10) >=31
 
}