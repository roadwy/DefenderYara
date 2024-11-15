
rule Trojan_Win64_XWorm_DA_MTB{
	meta:
		description = "Trojan:Win64/XWorm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 3a 2f 65 78 70 6c 6f 72 65 72 77 69 6e 2f 6d 65 77 6f 62 66 6d 2e 64 6c 6c } //1 C:/explorerwin/mewobfm.dll
		$a_81_1 = {46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 74 68 65 20 44 4c 4c } //1 Failed to load the DLL
		$a_81_2 = {43 3a 2f 65 78 70 6c 6f 72 65 72 77 69 2f 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //10 C:/explorerwi/explorer.exe
		$a_81_3 = {43 3a 2f 65 78 70 6c 6f 72 65 72 77 69 6e 2f 70 79 74 68 6f 6e 2e 65 78 65 } //1 C:/explorerwin/python.exe
		$a_81_4 = {43 3a 2f 65 78 70 6c 6f 72 65 72 77 69 2f 70 64 66 2e 64 6c 6c } //12 C:/explorerwi/pdf.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*12) >=13
 
}