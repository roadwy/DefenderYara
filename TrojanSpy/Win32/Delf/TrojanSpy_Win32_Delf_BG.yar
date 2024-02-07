
rule TrojanSpy_Win32_Delf_BG{
	meta:
		description = "TrojanSpy:Win32/Delf.BG,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {68 74 74 70 3a 2f 2f 6d 32 73 74 65 61 6c 65 72 2e 68 6f 73 74 69 6c 2e 70 6c 2f 63 2e 70 68 70 3f 6c 6f 67 69 3d } //01 00  http://m2stealer.hostil.pl/c.php?logi=
		$a_01_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 77 64 6d 67 72 2e 65 78 65 } //00 00  C:\Windows\wdmgr.exe
	condition:
		any of ($a_*)
 
}