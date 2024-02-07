
rule TrojanSpy_Win32_Delf_BE{
	meta:
		description = "TrojanSpy:Win32/Delf.BE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 74 70 54 72 61 6e 73 66 65 72 } //01 00  ftpTransfer
		$a_00_1 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2d 66 20 2d 69 6d 20 20 63 6d 64 2e 65 78 65 } //01 00  taskkill.exe -f -im  cmd.exe
		$a_00_2 = {63 6d 64 20 2f 6b 20 20 73 74 61 72 74 20 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  cmd /k  start C:\windows\system\svchost.exe
		$a_01_3 = {54 6f 64 6f 73 20 41 72 71 75 69 76 6f 73 } //01 00  Todos Arquivos
		$a_00_4 = {73 79 73 74 65 6d 5c 61 73 73 75 6e 2e 73 79 73 } //00 00  system\assun.sys
	condition:
		any of ($a_*)
 
}