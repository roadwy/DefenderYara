
rule TrojanSpy_Win32_Delf_BZ{
	meta:
		description = "TrojanSpy:Win32/Delf.BZ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 45 53 6e 69 66 66 65 72 31 55 52 4c 43 68 61 6e 67 65 } //3 IESniffer1URLChange
		$a_01_1 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //2 [Print Screen]
		$a_01_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 63 68 61 63 68 65 5c 43 75 72 72 65 6e 74 56 65 72 73 69 79 6f 6e 5c 57 69 6e 58 50 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //3 c:\windows\system\chache\CurrentVersiyon\WinXP\svchost.exe
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //1 Software\Microsoft\windows\currentversion\run
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=6
 
}