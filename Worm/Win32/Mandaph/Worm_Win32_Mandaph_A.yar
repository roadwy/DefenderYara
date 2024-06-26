
rule Worm_Win32_Mandaph_A{
	meta:
		description = "Worm:Win32/Mandaph.A,SIGNATURE_TYPE_PEHSTR_EXT,68 00 68 00 11 00 00 0a 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 64 6e 73 2d 62 6c 61 62 6c 61 2e 6f 72 67 2f 73 68 6c 2f } //0a 00  http://dns-blabla.org/shl/
		$a_00_1 = {63 66 74 6d 6f 6e 2e 65 78 65 } //0a 00  cftmon.exe
		$a_00_2 = {73 70 6f 6f 6c 73 2e 65 78 65 } //0a 00  spools.exe
		$a_00_3 = {6d 61 6e 64 61 2e 70 68 70 } //0a 00  manda.php
		$a_00_4 = {6c 6f 67 6f 6e 75 69 2e 65 78 65 } //0a 00  logonui.exe
		$a_00_5 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //0a 00  autorun.inf
		$a_00_6 = {5c 64 72 69 76 65 72 73 5c } //01 00  \drivers\
		$a_00_7 = {64 61 74 61 2e 70 68 70 } //01 00  data.php
		$a_00_8 = {76 62 73 2e 70 68 70 } //01 00  vbs.php
		$a_00_9 = {6e 74 75 73 65 72 } //01 00  ntuser
		$a_00_10 = {61 75 74 6f 6c 6f 61 64 } //01 00  autoload
		$a_00_11 = {5c 65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c } //01 00  \exefile\shell\open\command\
		$a_00_12 = {53 68 65 6c 6c 45 78 65 63 75 74 65 3d 61 75 74 6f 72 75 6e 2e 65 78 65 } //01 00  ShellExecute=autorun.exe
		$a_00_13 = {57 69 6e 45 78 65 63 } //0a 00  WinExec
		$a_00_14 = {53 b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed } //0a 00 
		$a_03_15 = {8b 45 fc 40 89 45 fc ff 75 08 ff 15 90 01 04 39 45 fc 7d 16 8b 45 08 03 45 fc 0f be 00 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5 90 00 } //0a 00 
		$a_03_16 = {85 c0 75 0d 68 80 4f 12 00 ff 15 90 01 02 83 00 eb 0b 68 10 27 00 00 ff 15 90 01 02 83 00 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}