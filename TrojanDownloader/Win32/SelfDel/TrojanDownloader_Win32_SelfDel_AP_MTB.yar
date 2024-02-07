
rule TrojanDownloader_Win32_SelfDel_AP_MTB{
	meta:
		description = "TrojanDownloader:Win32/SelfDel.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6b 00 6d 00 6d 00 73 00 63 00 68 00 6f 00 6f 00 6c 00 2e 00 6f 00 72 00 67 00 2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 61 00 61 00 25 00 64 00 2e 00 65 00 78 00 65 00 } //02 00  kmmschool.org/wp-content/aa%d.exe
		$a_01_1 = {38 00 6f 00 6c 00 70 00 38 00 37 00 36 00 6c 00 38 00 36 00 37 00 6c 00 } //02 00  8olp876l867l
		$a_01_2 = {6b 00 6d 00 6d 00 73 00 63 00 68 00 6f 00 6f 00 6c 00 2e 00 6f 00 72 00 67 00 2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 61 00 61 00 25 00 64 00 2e 00 70 00 68 00 70 00 } //01 00  kmmschool.org/wp-content/aa%d.php
		$a_01_3 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 57 } //01 00  InternetCrackUrlW
		$a_01_4 = {57 72 69 74 65 46 69 6c 65 } //00 00  WriteFile
	condition:
		any of ($a_*)
 
}