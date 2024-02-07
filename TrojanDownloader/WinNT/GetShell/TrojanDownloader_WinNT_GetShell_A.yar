
rule TrojanDownloader_WinNT_GetShell_A{
	meta:
		description = "TrojanDownloader:WinNT/GetShell.A,SIGNATURE_TYPE_JAVAHSTR_EXT,2d 00 28 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 61 76 61 2f 6e 65 74 2f 55 52 4c } //05 00  java/net/URL
		$a_01_1 = {6a 61 76 61 2f 6c 61 6e 67 2f 52 75 6e 74 69 6d 65 } //05 00  java/lang/Runtime
		$a_01_2 = {6a 61 76 61 2e 69 6f 2e 74 6d 70 64 69 72 } //05 00  java.io.tmpdir
		$a_01_3 = {63 68 6d 6f 64 20 37 35 35 } //05 00  chmod 755
		$a_01_4 = {43 4d 44 2e 65 78 65 20 2f 63 20 73 74 61 72 74 } //05 00  CMD.exe /c start
		$a_01_5 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 57 69 6e 64 6f 77 73 50 6f 77 65 72 73 68 65 6c 6c } //0a 00  Windows\System32\WindowsPowershell
		$a_01_6 = {12 b6 9b 2a 12 b6 3a 04 36 19 12 b6 99 12 } //0a 00 
		$a_01_7 = {19 12 b6 9b 2a 12 b6 3a } //00 00 
		$a_00_8 = {5d 04 00 00 6a ab 02 80 5c 22 00 00 6b ab 02 80 00 00 01 00 06 00 0c 00 84 21 47 65 74 53 68 65 6c 6c 2e } //41 00 
	condition:
		any of ($a_*)
 
}