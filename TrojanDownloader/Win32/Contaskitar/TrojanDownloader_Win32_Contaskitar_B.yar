
rule TrojanDownloader_Win32_Contaskitar_B{
	meta:
		description = "TrojanDownloader:Win32/Contaskitar.B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 09 00 00 04 00 "
		
	strings :
		$a_01_0 = {67 6f 6f 2e 67 6c 2f 4e 4d 51 76 41 } //04 00  goo.gl/NMQvA
		$a_01_1 = {67 6f 6f 2e 67 6c 2f 57 51 6f 46 44 } //04 00  goo.gl/WQoFD
		$a_01_2 = {67 6f 6f 2e 67 6c 2f 59 36 66 4c 46 6a } //02 00  goo.gl/Y6fLFj
		$a_01_3 = {2d 61 66 66 69 6c 69 64 3d 31 32 37 34 30 32 } //01 00  -affilid=127402
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 6e 61 74 69 6f 6e 7a 6f 6f 6d 53 6f 66 74 77 61 72 65 } //01 00  SOFTWARE\nationzoomSoftware
		$a_01_5 = {36 34 33 32 4e 6f 64 65 5c 42 65 61 74 54 6f 6f 6c } //01 00  6432Node\BeatTool
		$a_01_6 = {2f 61 66 6c 74 3d 70 63 30 31 30 32 20 2f 69 6e 73 74 6c 52 65 66 3d 70 63 30 31 30 32 20 2f 72 76 74 20 2f 70 72 6f 64 3a 64 65 66 } //01 00  /aflt=pc0102 /instlRef=pc0102 /rvt /prod:def
		$a_01_7 = {55 6e 69 6e 73 74 61 6c 6c 5c 61 76 61 73 74 } //01 00  Uninstall\avast
		$a_01_8 = {34 41 41 34 36 44 34 39 2d 34 35 39 46 2d 34 33 35 38 2d 42 34 44 31 2d 31 36 39 30 34 38 35 34 37 43 32 33 } //00 00  4AA46D49-459F-4358-B4D1-169048547C23
		$a_00_9 = {5d 04 00 00 06 44 03 80 5c 21 00 } //00 07 
	condition:
		any of ($a_*)
 
}