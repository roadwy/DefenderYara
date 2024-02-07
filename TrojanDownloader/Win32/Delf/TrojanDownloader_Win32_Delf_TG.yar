
rule TrojanDownloader_Win32_Delf_TG{
	meta:
		description = "TrojanDownloader:Win32/Delf.TG,SIGNATURE_TYPE_PEHSTR_EXT,21 00 1f 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {68 74 74 70 3a 2f 2f 63 70 6b 2e 65 61 73 79 37 38 2e 63 6e 2f 63 6f 75 6e 74 2f 63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d } //0a 00  http://cpk.easy78.cn/count/count.asp?mac=
		$a_01_2 = {54 00 4d 00 45 00 53 00 53 00 53 00 41 00 4e 00 47 00 45 00 52 00 } //01 00  TMESSSANGER
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 } //01 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3
		$a_00_5 = {41 70 70 45 76 65 6e 74 73 5c 53 63 68 65 6d 65 73 5c 41 70 70 73 5c 45 78 70 6c 6f 72 65 72 5c 4e 61 76 69 67 61 74 69 6e 67 5c 2e 43 75 72 72 65 6e 74 } //00 00  AppEvents\Schemes\Apps\Explorer\Navigating\.Current
	condition:
		any of ($a_*)
 
}