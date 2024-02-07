
rule TrojanDownloader_Win32_Adialer_NAB{
	meta:
		description = "TrojanDownloader:Win32/Adialer.NAB,SIGNATURE_TYPE_PEHSTR,39 00 38 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6e 65 74 77 6f 72 6b 2e 6e 6f 63 72 65 64 69 74 63 61 72 64 2e 63 6f 6d 2f 44 69 61 6c 48 54 4d 4c 2f 4f 53 42 2f 66 69 6e 61 6c 2e 70 68 70 33 } //0a 00  http://network.nocreditcard.com/DialHTML/OSB/final.php3
		$a_01_1 = {68 74 74 70 3a 2f 2f 6e 65 74 77 6f 72 6b 2e 6e 6f 63 72 65 64 69 74 63 61 72 64 2e 63 6f 6d 2f 44 69 61 6c 48 54 4d 4c 2f 4f 53 42 2f 77 61 69 74 2e 70 68 70 33 } //0a 00  http://network.nocreditcard.com/DialHTML/OSB/wait.php3
		$a_01_2 = {52 41 53 50 48 4f 4e 45 2e 45 58 45 } //0a 00  RASPHONE.EXE
		$a_01_3 = {72 6e 61 75 69 2e 64 6c 6c 2c 52 6e 61 44 69 61 6c } //0a 00  rnaui.dll,RnaDial
		$a_01_4 = {44 48 54 4d 4c 41 63 63 65 73 73 2e 44 4c 4c } //01 00  DHTMLAccess.DLL
		$a_01_5 = {44 69 73 63 6f 6e 6e 65 63 74 69 6e 67 2e 2e 2e } //01 00  Disconnecting...
		$a_01_6 = {57 6f 75 6c 64 20 79 6f 75 20 64 69 73 63 6f 6e 6e 65 63 74 20 3f } //01 00  Would you disconnect ?
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE
		$a_01_8 = {52 61 73 47 65 74 43 6f 6e 6e 65 63 74 53 74 61 74 75 73 41 } //01 00  RasGetConnectStatusA
		$a_01_9 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 41 } //01 00  RasEnumConnectionsA
		$a_01_10 = {52 61 73 48 61 6e 67 55 70 41 } //01 00  RasHangUpA
		$a_01_11 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}