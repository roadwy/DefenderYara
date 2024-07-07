
rule TrojanDownloader_Win32_Banload_BFT{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 00 73 00 79 00 72 00 69 00 63 00 6f 00 2e 00 7a 00 69 00 70 00 } //1 psyrico.zip
		$a_01_1 = {73 00 6e 00 64 00 36 00 34 00 2e 00 7a 00 69 00 70 00 } //1 snd64.zip
		$a_01_2 = {73 00 6e 00 64 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 snd32.exe
		$a_03_3 = {2e 00 65 00 78 00 65 00 90 02 08 68 00 74 00 74 00 70 00 90 00 } //1
		$a_01_4 = {6d 65 75 64 65 75 73 33 33 33 } //1 meudeus333
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}