
rule Ransom_MSIL_FileCoder_MVE_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 6c 63 44 69 66 2e 65 78 65 } //AlcDif.exe  3
		$a_80_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_00_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All your files are encrypted
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}