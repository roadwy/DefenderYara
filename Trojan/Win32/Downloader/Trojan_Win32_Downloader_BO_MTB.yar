
rule Trojan_Win32_Downloader_BO_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 53 00 61 00 6d 00 70 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //1 C:\Sample.exe
		$a_01_1 = {65 00 78 00 69 00 74 00 5f 00 63 00 6f 00 64 00 65 00 2e 00 74 00 78 00 74 00 } //1 exit_code.txt
		$a_80_2 = {50 4f 57 45 52 53 48 45 4c 4c } //POWERSHELL  1
		$a_01_3 = {52 75 6e 20 53 61 6d 70 6c 65 20 76 31 } //1 Run Sample v1
		$a_01_4 = {43 3a 5c 63 5f 63 6f 64 65 5c 68 65 6c 70 65 72 5c 77 69 6e 64 6f 77 73 5c 65 78 65 63 75 74 65 72 5c 52 65 6c 65 61 73 65 5c 65 78 65 63 75 74 65 72 2e 70 64 62 } //1 C:\c_code\helper\windows\executer\Release\executer.pdb
		$a_01_5 = {6c 00 6f 00 61 00 64 00 64 00 6c 00 6c 00 5f 00 78 00 38 00 36 00 2e 00 65 00 78 00 65 00 } //1 loaddll_x86.exe
		$a_01_6 = {25 00 73 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 %s\Shell\Open\Command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}