
rule Trojan_Win32_Delf_CR{
	meta:
		description = "Trojan:Win32/Delf.CR,SIGNATURE_TYPE_PEHSTR,ffffff8d 00 ffffff8c 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {77 6f 72 6d 6f 72 6b 75 74 2e 70 68 70 } //10 wormorkut.php
		$a_01_2 = {63 6c 61 73 73 3d 75 73 65 72 65 6d 61 69 6c } //10 class=useremail
		$a_01_3 = {64 65 6c 20 64 65 6c 65 78 65 63 2e 62 61 74 } //10 del delexec.bat
		$a_01_4 = {74 61 73 6b 6b 69 6c 6c 20 2d 66 20 2d 69 6d 20 63 74 66 6d 75 6e 2e 65 78 65 } //10 taskkill -f -im ctfmun.exe
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1) >=140
 
}