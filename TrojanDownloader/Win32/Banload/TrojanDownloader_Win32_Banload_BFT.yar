
rule TrojanDownloader_Win32_Banload_BFT{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 73 00 79 00 72 00 69 00 63 00 6f 00 2e 00 7a 00 69 00 70 00 } //01 00  psyrico.zip
		$a_01_1 = {73 00 6e 00 64 00 36 00 34 00 2e 00 7a 00 69 00 70 00 } //01 00  snd64.zip
		$a_01_2 = {73 00 6e 00 64 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00  snd32.exe
		$a_03_3 = {2e 00 65 00 78 00 65 00 90 02 08 68 00 74 00 74 00 70 00 90 00 } //01 00 
		$a_01_4 = {6d 65 75 64 65 75 73 33 33 33 } //00 00  meudeus333
		$a_00_5 = {80 10 00 } //00 22 
	condition:
		any of ($a_*)
 
}