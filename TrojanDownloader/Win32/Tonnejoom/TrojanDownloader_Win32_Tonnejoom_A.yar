
rule TrojanDownloader_Win32_Tonnejoom_A{
	meta:
		description = "TrojanDownloader:Win32/Tonnejoom.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 6f 6f 6d 6c 61 2e 65 64 75 68 69 2e 61 74 2f 76 73 32 38 2f 73 63 68 75 6c 65 2f 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 2f 63 6f 6d 70 6f 6e 65 6e 74 73 2f 63 6f 6d 5f 70 68 6f 63 61 67 61 6c 6c 65 72 79 2f 63 2e 65 78 65 } //02 00  joomla.eduhi.at/vs28/schule/administrator/components/com_phocagallery/c.exe
		$a_01_1 = {77 2e 73 63 68 77 65 69 7a 65 72 68 6f 66 2d 77 65 74 7a 69 6b 6f 6e 2e 63 68 2f 69 6d 61 67 65 73 2f 72 74 75 63 72 74 6d 69 72 75 6d 63 74 72 75 74 62 69 74 75 65 72 69 75 6d 78 65 2f 69 76 6f 74 79 69 6d 6f 79 63 74 6f 72 69 65 6f 74 63 6d 69 72 2e 65 78 65 } //01 00  w.schweizerhof-wetzikon.ch/images/rtucrtmirumctrutbitueriumxe/ivotyimoyctorieotcmir.exe
		$a_03_2 = {8b c8 83 e1 03 8a 0c 11 30 88 90 01 03 00 40 83 f8 52 72 ec b8 90 01 03 00 8d 48 01 90 90 8a 10 40 84 d2 75 f9 90 00 } //01 00 
		$a_03_3 = {6a 05 6a 60 e8 90 01 02 00 00 8d 14 40 c1 e2 08 bf ff ff ff 7f 6a 01 2b fa e8 90 00 } //01 00 
		$a_01_4 = {85 f6 76 12 8b ff 8b d0 83 e2 03 8a 14 0a 30 14 38 40 3b c6 72 f0 8b c7 } //01 00 
		$a_01_5 = {eb 02 33 c9 8b c3 c1 e8 08 8b d3 88 19 c1 eb 18 88 41 01 c1 ea 10 33 c0 88 59 03 88 51 02 } //01 00 
		$a_01_6 = {2f 70 75 72 65 74 6f 6e 6e 65 6c 2e 6e 65 74 2f 33 64 65 73 6f 6e 6e 65 6c 2e 6a 73 } //01 00  /puretonnel.net/3desonnel.js
		$a_01_7 = {77 77 77 2e 65 61 73 79 63 6f 75 6e 74 65 72 2e 63 6f 6d 2f 63 6f 75 6e 74 65 72 2e 70 68 70 3f 76 74 72 74 76 72 76 74 72 74 76 65 72 74 76 72 } //01 00  www.easycounter.com/counter.php?vtrtvrvtrtvertvr
		$a_01_8 = {2e 63 6f 6d 2f 63 6f 75 6e 74 65 72 2e 70 68 70 3f 74 63 72 63 72 63 65 72 65 72 65 72 77 62 76 62 62 72 74 64 66 } //00 00  .com/counter.php?tcrcrcerererwbvbbrtdf
		$a_00_9 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}