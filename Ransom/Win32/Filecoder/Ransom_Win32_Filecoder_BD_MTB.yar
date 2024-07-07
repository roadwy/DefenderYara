
rule Ransom_Win32_Filecoder_BD_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //3 delete shadows /all /quiet
		$a_81_1 = {73 79 73 6e 61 74 69 76 65 5c 76 73 73 61 64 6d 69 6e 2e 65 78 65 } //3 sysnative\vssadmin.exe
		$a_81_2 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All your files have been encrypted
		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your files are encrypted
		$a_81_4 = {62 61 62 79 66 72 6f 6d 70 61 72 61 64 69 73 65 } //1 babyfromparadise
		$a_81_5 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 2f 66 20 2f 71 } //1 cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}