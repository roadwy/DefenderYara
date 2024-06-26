
rule TrojanDownloader_Win32_Delf_GD{
	meta:
		description = "TrojanDownloader:Win32/Delf.GD,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 1a 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 20 2f 90 02 04 2e 65 78 65 90 00 } //01 00 
		$a_00_1 = {5c 73 76 63 68 31 73 74 2e 65 78 65 } //01 00  \svch1st.exe
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 61 64 76 61 6e 63 65 64 5c 66 6f 6c 64 65 72 5c 68 69 64 64 65 6e 5c 73 68 6f 77 61 6c 6c } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\advanced\folder\hidden\showall
		$a_00_3 = {5c 73 6e 6f 77 2e 65 78 65 } //01 00  \snow.exe
		$a_00_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 61 74 65 20 32 30 30 32 2d 30 38 2d 32 38 } //01 00  cmd.exe /c date 2002-08-28
		$a_00_5 = {5c 77 69 6e 73 73 2e 73 79 73 } //01 00  \winss.sys
		$a_00_6 = {72 61 76 6d 6f 6e 2e 65 78 65 } //01 00  ravmon.exe
		$a_00_7 = {72 61 76 6d 6f 6e 64 2e 65 78 65 } //01 00  ravmond.exe
		$a_00_8 = {61 76 70 2e 65 78 65 } //01 00  avp.exe
		$a_00_9 = {61 76 70 2e 63 6f 6d } //01 00  avp.com
		$a_00_10 = {63 63 65 6e 74 65 72 2e 65 78 65 } //01 00  ccenter.exe
		$a_00_11 = {33 36 30 53 61 66 65 2e 65 78 65 } //01 00  360Safe.exe
		$a_00_12 = {33 36 30 74 72 61 79 2e 65 78 65 } //01 00  360tray.exe
		$a_00_13 = {56 73 54 73 6b 4d 67 72 2e 65 78 65 } //01 00  VsTskMgr.exe
		$a_00_14 = {41 53 54 2e 45 58 45 } //01 00  AST.EXE
		$a_00_15 = {6b 76 73 72 76 78 70 2e 65 78 65 } //01 00  kvsrvxp.exe
		$a_00_16 = {73 63 61 6e 33 32 2e 65 78 65 } //01 00  scan32.exe
		$a_00_17 = {41 76 4d 6f 6e 69 74 6f 72 2e 65 78 65 } //01 00  AvMonitor.exe
		$a_00_18 = {41 4e 54 49 41 52 50 2e 65 78 65 } //01 00  ANTIARP.exe
		$a_00_19 = {79 61 68 6f 6f 6d 65 73 73 65 6e 67 65 72 } //01 00  yahoomessenger
		$a_00_20 = {74 72 69 6c 6c 69 61 6e 2e 65 78 65 } //01 00  trillian.exe
		$a_00_21 = {73 6b 79 70 65 2e } //01 00  skype.
		$a_00_22 = {67 6f 6f 67 6c 65 74 61 6c 6b 2e } //01 00  googletalk.
		$a_00_23 = {55 00 52 00 4c 00 4c 00 57 00 49 00 4e 00 53 00 53 00 } //01 00  URLLWINSS
		$a_02_24 = {6a 00 6a 00 68 90 01 02 40 00 a1 90 01 02 40 00 50 6a 00 e8 90 01 02 ff ff 6a 00 68 90 01 02 40 00 e8 90 01 02 ff ff 6a 00 6a 00 68 90 01 02 40 00 a1 90 01 02 40 00 50 6a 00 e8 90 01 02 ff ff 6a 00 68 90 01 02 40 00 e8 90 01 02 ff ff 6a 00 6a 00 68 90 01 02 40 00 a1 90 01 02 40 00 50 6a 00 e8 90 01 02 ff ff 6a 00 68 90 01 02 40 00 e8 90 01 02 ff ff 6a 00 90 00 } //01 00 
		$a_00_25 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}