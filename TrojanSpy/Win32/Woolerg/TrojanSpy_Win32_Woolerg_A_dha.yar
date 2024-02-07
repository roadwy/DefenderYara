
rule TrojanSpy_Win32_Woolerg_A_dha{
	meta:
		description = "TrojanSpy:Win32/Woolerg.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 72 53 54 55 50 20 3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 53 74 61 72 74 75 70 22 29 } //01 00  strSTUP = WshShell.SpecialFolders("Startup")
		$a_01_1 = {73 65 74 20 6f 53 68 65 6c 6c 4c 69 6e 6b 20 3d 20 57 73 68 53 68 65 6c 6c 2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 73 74 72 53 54 55 50 20 26 20 22 5c 57 69 6e 44 65 66 65 6e 64 65 72 2e 6c 6e 6b 22 29 } //01 00  set oShellLink = WshShell.CreateShortcut(strSTUP & "\WinDefender.lnk")
		$a_01_2 = {77 6c 67 2e 64 61 74 } //01 00  wlg.dat
		$a_00_3 = {31 00 30 00 37 00 2e 00 36 00 2e 00 31 00 38 00 31 00 2e 00 31 00 31 00 } //00 00  107.6.181.11
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}