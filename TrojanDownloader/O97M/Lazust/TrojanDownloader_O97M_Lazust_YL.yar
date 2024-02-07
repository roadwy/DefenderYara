
rule TrojanDownloader_O97M_Lazust_YL{
	meta:
		description = "TrojanDownloader:O97M/Lazust.YL,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 57 69 6e 45 78 65 63 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 } //01 00  Declare PtrSafe Function WinExec Lib "kernel32"
		$a_00_1 = {61 75 72 69 3d } //14 00  auri=
		$a_00_2 = {63 7a 69 6e 66 6f 2e 63 6c 75 62 2f 63 6f 6d 6d 6f 6e 2e 70 68 70 } //14 00  czinfo.club/common.php
		$a_00_3 = {70 65 67 61 73 75 73 63 6f 2e 6e 65 74 2f 61 63 69 64 65 2e 70 68 70 } //14 00  pegasusco.net/acide.php
		$a_00_4 = {73 6d 69 6c 65 6b 65 65 70 65 72 73 2e 63 6f 2f 73 6d 69 6c 65 2e 70 68 70 } //00 00  smilekeepers.co/smile.php
		$a_00_5 = {5d 04 00 00 32 ec 03 80 5c 34 00 00 34 ec 03 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}