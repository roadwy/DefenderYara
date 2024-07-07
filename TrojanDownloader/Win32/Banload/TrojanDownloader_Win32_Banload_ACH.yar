
rule TrojanDownloader_Win32_Banload_ACH{
	meta:
		description = "TrojanDownloader:Win32/Banload.ACH,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 07 00 00 "
		
	strings :
		$a_03_0 = {45 4d 31 30 90 09 04 00 49 4d 41 47 90 00 } //10
		$a_03_1 = {47 45 4d 36 90 09 03 00 49 4d 41 90 00 } //10
		$a_01_2 = {5c 44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c } //10 \Dados de aplicativos\
		$a_03_3 = {6e 66 44 6f 77 6e 90 09 02 00 43 6f 90 00 } //5
		$a_01_4 = {01 1b 44 6f 77 6e 6c 6f 61 64 65 72 } //1 ᬁ潄湷潬摡牥
		$a_01_5 = {01 ba 49 65 78 70 6c 6f 72 65 72 } //5
		$a_01_6 = {55 70 41 70 70 33 32 2e 64 6c 6c } //1 UpApp32.dll
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_03_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1) >=36
 
}