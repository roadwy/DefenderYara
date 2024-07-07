
rule TrojanDownloader_Win32_Liucale_A{
	meta:
		description = "TrojanDownloader:Win32/Liucale.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 2d 8b 84 24 20 04 00 00 8d 8c 24 18 02 00 00 50 51 e8 90 01 04 83 c4 08 85 c0 75 11 8d 94 24 18 02 00 00 55 52 e8 90 01 04 83 c4 08 f6 46 0c 10 74 99 90 00 } //1
		$a_03_1 = {b3 0a 81 fe 00 04 00 00 7d 47 6a 00 8d 4c 24 17 6a 01 51 55 ff 15 90 01 04 8a 54 24 13 88 94 34 90 01 02 00 00 46 83 fe 04 7c d7 90 00 } //1
		$a_01_2 = {43 6f 75 6e 74 2e 41 73 70 3f 61 3d } //1 Count.Asp?a=
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}