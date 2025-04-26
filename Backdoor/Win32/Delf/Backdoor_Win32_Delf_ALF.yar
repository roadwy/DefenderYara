
rule Backdoor_Win32_Delf_ALF{
	meta:
		description = "Backdoor:Win32/Delf.ALF,SIGNATURE_TYPE_PEHSTR,29 00 29 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //10 explorerbar
		$a_01_1 = {63 3a 5c 61 75 74 6f 65 78 65 2e 65 78 65 } //10 c:\autoexe.exe
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_3 = {68 74 74 70 3a 2f 2f 32 30 37 2e 35 38 2e 31 36 32 2e 32 33 37 2f 73 70 79 2f 63 61 72 74 61 6f 2e 73 63 72 } //10 http://207.58.162.237/spy/cartao.scr
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1) >=41
 
}