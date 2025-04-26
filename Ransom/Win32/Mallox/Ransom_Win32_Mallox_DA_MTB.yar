
rule Ransom_Win32_Mallox_DA_MTB{
	meta:
		description = "Ransom:Win32/Mallox.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 61 6e 74 20 73 65 6e 64 20 74 61 72 67 65 74 20 69 6e 66 6f 20 64 61 74 61 20 74 6f 20 74 68 65 20 73 65 72 76 65 72 } //1 Cant send target info data to the server
		$a_81_1 = {48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 2e 74 78 74 } //1 HOW TO DECRYPT.txt
		$a_81_2 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 delete shadows /all /quiet
		$a_81_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 } //1 vssadmin.exe
		$a_81_4 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 } //1 taskkill.exe
		$a_81_5 = {2e 6d 61 6c 6c 6f 78 } //1 .mallox
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}