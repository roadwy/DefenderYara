
rule TrojanDownloader_Win32_Banload_BGG{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 37 00 34 00 2e 00 36 00 33 00 2e 00 32 00 31 00 33 00 2e 00 32 00 30 00 2f 00 } //1 /74.63.213.20/
		$a_03_1 = {2e 00 7a 00 69 00 70 00 00 00 90 02 02 67 31 67 32 00 00 00 00 6f 00 70 00 65 00 6e 00 90 00 } //1
		$a_01_2 = {8a 0a 8d 52 01 88 08 8d 40 01 84 c9 75 f2 8b c6 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}