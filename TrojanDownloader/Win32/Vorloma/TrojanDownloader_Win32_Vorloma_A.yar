
rule TrojanDownloader_Win32_Vorloma_A{
	meta:
		description = "TrojanDownloader:Win32/Vorloma.A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffdb 01 ffffffcc 01 0e 00 00 ffffffc8 00 "
		
	strings :
		$a_01_0 = {64 74 6f 70 74 6f 6f 6c 2e 63 6f 6d 2f 70 64 73 2f 6c 61 75 6e 63 68 65 72 2f } //c8 00  dtoptool.com/pds/launcher/
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4e 56 49 44 49 41 2e 65 78 65 } //14 00  C:\Program Files\NVIDIA.exe
		$a_01_2 = {67 75 69 64 65 2e 61 6c 6c 62 6c 65 74 2e 6e 65 74 2f 61 6c 6c 62 6c 65 74 2e 70 68 70 } //14 00  guide.allblet.net/allblet.php
		$a_01_3 = {4c 61 75 6e 63 68 65 72 5c 6d 69 6e 69 4c 61 75 6e 63 68 65 72 2e 65 78 65 } //14 00  Launcher\miniLauncher.exe
		$a_01_4 = {44 65 6c 5a 69 70 31 39 30 2e 64 6c 6c } //1e 00  DelZip190.dll
		$a_01_5 = {64 74 6f 70 74 6f 6f 6c 5f 76 33 } //0a 00  dtoptool_v3
		$a_01_6 = {5c 64 74 63 5c 64 61 74 78 } //0a 00  \dtc\datx
		$a_01_7 = {5c 75 74 5c 4d 69 6e 69 4c 61 75 6e 63 68 65 72 2e 65 78 65 } //0a 00  \ut\MiniLauncher.exe
		$a_01_8 = {5c 57 4c 61 75 6e 63 68 65 72 5c 77 4c 61 75 6e 63 68 65 72 2e 65 78 65 } //05 00  \WLauncher\wLauncher.exe
		$a_01_9 = {57 61 72 63 72 61 66 74 20 49 49 49 2e 65 78 65 } //05 00  Warcraft III.exe
		$a_01_10 = {46 72 6f 7a 65 6e 20 54 68 72 6f 6e 65 2e 65 78 65 } //05 00  Frozen Throne.exe
		$a_01_11 = {77 61 72 33 5f 6f 72 69 67 69 6e 61 6c 5f 72 75 6e } //05 00  war3_original_run
		$a_01_12 = {6c 69 6e 65 61 67 65 5f 74 65 73 74 5f 72 75 6e } //05 00  lineage_test_run
		$a_01_13 = {77 6f 77 5f 61 64 64 6f 6e 5f 64 65 6c 65 74 65 } //00 00  wow_addon_delete
	condition:
		any of ($a_*)
 
}