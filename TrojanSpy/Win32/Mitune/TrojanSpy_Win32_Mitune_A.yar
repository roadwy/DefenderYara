
rule TrojanSpy_Win32_Mitune_A{
	meta:
		description = "TrojanSpy:Win32/Mitune.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 14 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 70 70 6c 65 2e 63 6f 6d 2f 69 74 75 6e 65 73 2f } //01 00  apple.com/itunes/
		$a_00_1 = {43 61 6e 27 74 20 66 6f 75 6e 64 20 74 68 65 20 69 54 75 6e 65 73 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d } //01 00  Can't found the iTunes on your system
		$a_00_2 = {41 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 61 20 69 54 75 6e 65 73 20 6e 6f 77 } //01 00  Are you want to download a iTunes now
		$a_00_3 = {6d 75 73 69 63 6d 61 74 63 68 2e 63 6f 6d } //01 00  musicmatch.com
		$a_00_4 = {43 61 6e 27 74 20 66 6f 75 6e 64 20 74 68 65 20 4d 75 73 69 63 4d 61 74 63 68 20 4a 75 6b 65 62 6f 78 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d } //01 00  Can't found the MusicMatch Jukebox on your system
		$a_00_5 = {41 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 61 20 4d 55 53 49 43 4d 41 54 43 48 20 4a 75 6b 65 62 6f 78 20 6e 6f 77 } //01 00  Are you want to download a MUSICMATCH Jukebox now
		$a_00_6 = {73 6e 64 72 65 63 33 32 2e 65 78 65 } //01 00  sndrec32.exe
		$a_00_7 = {73 6e 64 76 6f 6c 33 32 2e 65 78 65 } //01 00  sndvol32.exe
		$a_00_8 = {63 64 70 6c 61 79 65 72 2e 65 78 65 } //01 00  cdplayer.exe
		$a_00_9 = {77 6d 70 6c 61 79 65 72 2e 65 78 65 } //01 00  wmplayer.exe
		$a_00_10 = {46 52 4f 4e 54 50 47 2e 45 58 45 } //01 00  FRONTPG.EXE
		$a_00_11 = {50 4f 57 45 52 50 4e 54 2e 45 58 45 } //01 00  POWERPNT.EXE
		$a_00_12 = {45 58 43 45 4c 2e 45 58 45 } //01 00  EXCEL.EXE
		$a_00_13 = {57 49 4e 57 4f 52 44 2e 45 58 45 } //01 00  WINWORD.EXE
		$a_00_14 = {6d 73 70 61 69 6e 74 2e 65 78 65 } //01 00  mspaint.exe
		$a_00_15 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //01 00  notepad.exe
		$a_00_16 = {63 61 6c 63 2e 65 78 65 } //01 00  calc.exe
		$a_00_17 = {6d 73 69 6d 6e 2e 65 78 65 } //01 00  msimn.exe
		$a_00_18 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //01 00  OpenClipboard
		$a_01_19 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00  SetClipboardData
	condition:
		any of ($a_*)
 
}