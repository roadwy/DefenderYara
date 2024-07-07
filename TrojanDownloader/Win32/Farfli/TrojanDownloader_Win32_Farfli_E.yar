
rule TrojanDownloader_Win32_Farfli_E{
	meta:
		description = "TrojanDownloader:Win32/Farfli.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 44 24 2c 44 c6 44 24 2d 6c c6 44 24 2e 6c c6 44 24 2f 46 c6 44 24 30 75 c6 44 24 31 55 c6 44 24 32 70 c6 44 24 33 67 c6 44 24 34 72 c6 44 24 35 61 c6 44 24 36 64 c6 44 24 37 72 c6 44 24 38 73 88 5c 24 39 51 ff 15 90 01 02 40 00 90 00 } //1
		$a_01_1 = {b9 ab 05 00 00 25 ff 00 00 00 99 f7 f9 8b da 80 c3 3d e8 69 0a 00 00 8b 74 24 10 85 f6 76 10 8b 44 24 0c 8a 10 32 d3 02 d3 88 10 40 4e 75 f4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}