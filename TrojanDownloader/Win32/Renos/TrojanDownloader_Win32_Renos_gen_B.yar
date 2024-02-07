
rule TrojanDownloader_Win32_Renos_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0a 00 09 00 00 03 00 "
		
	strings :
		$a_00_0 = {53 79 73 74 65 6d 20 41 6c 65 72 74 21 } //03 00  System Alert!
		$a_00_1 = {71 56 4c 5d 4a 56 5d 4c 6a 5d 59 5c 7e 51 54 5d } //02 00  qVL]JV]Lj]Y\~QT]
		$a_00_2 = {53 70 79 4c 6f 63 6b 65 64 } //03 00  SpyLocked
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 70 79 6c 6f 63 6b 65 64 2e 63 6f 6d 2f 3f } //03 00  http://www.spylocked.com/?
		$a_00_4 = {68 74 74 70 3a 2f 2f 6b 65 72 61 74 6f 6d 69 72 2e 62 69 7a 2f 67 65 74 2e 70 68 70 3f 70 61 72 74 6e 65 72 3d } //02 00  http://keratomir.biz/get.php?partner=
		$a_00_5 = {44 69 73 70 6c 61 79 49 63 6f 6e } //02 00  DisplayIcon
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //02 00  InternetOpenA
		$a_00_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c } //03 00  InternetOpenUrl
		$a_00_8 = {53 79 73 74 65 6d 20 68 61 73 20 64 65 74 65 63 74 65 64 20 61 20 6e 75 6d 62 65 72 20 6f 66 20 61 63 74 69 76 65 20 73 70 79 77 61 72 65 20 61 70 70 6c 69 63 61 74 69 6f 6e 73 20 74 68 61 74 20 6d 61 79 20 69 6d 70 61 63 74 20 74 68 65 20 70 65 72 66 6f 72 6d 61 6e 63 65 20 6f 66 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2e } //00 00  System has detected a number of active spyware applications that may impact the performance of your computer.
	condition:
		any of ($a_*)
 
}