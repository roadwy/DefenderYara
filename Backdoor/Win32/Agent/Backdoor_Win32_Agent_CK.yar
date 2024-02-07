
rule Backdoor_Win32_Agent_CK{
	meta:
		description = "Backdoor:Win32/Agent.CK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4e 54 62 6f 6f 74 2e 65 78 65 } //01 00  \NTboot.exe
		$a_01_1 = {44 61 72 6b 53 68 65 6c 6c 5c 52 65 6c 65 61 73 65 5c 44 61 72 6b 53 68 65 6c 6c 2e 70 64 62 } //01 00  DarkShell\Release\DarkShell.pdb
		$a_01_2 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //01 00  program files\Internet Explorer\IEXPLORE.EXE
		$a_01_3 = {44 61 72 6b 53 68 65 6c 6c 2e 64 6c 6c } //01 00  DarkShell.dll
		$a_01_4 = {44 6f 77 6e 43 74 72 6c 41 6c 74 44 65 6c } //01 00  DownCtrlAltDel
		$a_01_5 = {44 00 61 00 72 00 6b 00 53 00 68 00 65 00 6c 00 6c 00 5f 00 45 00 76 00 65 00 6e 00 74 00 5f 00 53 00 74 00 61 00 72 00 74 00 57 00 61 00 69 00 74 00 } //01 00  DarkShell_Event_StartWait
		$a_01_6 = {44 00 61 00 72 00 6b 00 53 00 68 00 65 00 6c 00 6c 00 5f 00 45 00 76 00 65 00 6e 00 74 00 5f 00 53 00 74 00 6f 00 70 00 57 00 61 00 69 00 74 00 } //01 00  DarkShell_Event_StopWait
		$a_00_7 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5f 00 53 00 65 00 72 00 76 00 65 00 72 00 } //01 00  Internet Explorer_Server
		$a_01_8 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 22 00 25 00 73 00 22 00 20 00 22 00 25 00 73 00 22 00 } //01 00  cmd.exe /c "%s" "%s"
		$a_01_9 = {53 00 74 00 61 00 72 00 74 00 5f 00 57 00 61 00 69 00 74 00 5f 00 25 00 73 00 } //01 00  Start_Wait_%s
		$a_01_10 = {53 00 74 00 6f 00 70 00 57 00 61 00 69 00 74 00 5f 00 25 00 73 00 } //00 00  StopWait_%s
	condition:
		any of ($a_*)
 
}