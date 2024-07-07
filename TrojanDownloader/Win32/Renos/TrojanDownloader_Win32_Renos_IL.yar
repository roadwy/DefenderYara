
rule TrojanDownloader_Win32_Renos_IL{
	meta:
		description = "TrojanDownloader:Win32/Renos.IL,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {2f 73 63 61 6e 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 74 79 70 65 3d 25 73 26 73 61 69 64 3d 25 73 26 76 65 72 3d 25 73 } //2 /scan/download.php?type=%s&said=%s&ver=%s
		$a_01_1 = {2f 70 62 70 72 6f 2f 73 74 61 74 73 2f 63 6e 74 2e 70 68 70 3f 74 79 70 65 3d 25 73 26 73 61 69 64 3d 25 73 26 76 65 72 3d 25 73 } //2 /pbpro/stats/cnt.php?type=%s&said=%s&ver=%s
		$a_01_2 = {57 69 7a 61 72 64 45 78 74 65 6e 74 69 6f 6e } //2 WizardExtention
		$a_01_3 = {61 74 69 77 69 7a 61 72 64 2e 65 78 65 } //1 atiwizard.exe
		$a_01_4 = {69 65 77 69 7a 61 72 64 2e 64 6c 6c } //1 iewizard.dll
		$a_01_5 = {4d 6f 7a 69 6c 6c 61 20 34 2e 30 20 28 53 74 61 74 42 6f 74 29 } //1 Mozilla 4.0 (StatBot)
		$a_01_6 = {6c 5f 69 6e 73 74 61 6c 6c } //1 l_install
		$a_01_7 = {ff d0 8b 10 6a 01 8b c8 8b 02 55 ff d0 } //2
		$a_03_8 = {6a 04 52 56 ff 15 90 01 04 56 ff d3 8b 44 24 1c 50 ff d3 8d 45 f0 c6 44 24 38 01 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*2+(#a_03_8  & 1)*2) >=10
 
}