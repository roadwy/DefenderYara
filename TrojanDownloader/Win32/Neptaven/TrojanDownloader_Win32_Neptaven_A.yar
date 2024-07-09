
rule TrojanDownloader_Win32_Neptaven_A{
	meta:
		description = "TrojanDownloader:Win32/Neptaven.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 02 00 00 80 c7 45 d0 57 61 72 65 c7 45 d4 5c 4d 69 63 } //3
		$a_03_1 = {33 c9 39 4c 24 08 7e 10 8b 44 24 04 03 c1 80 30 ?? 41 3b 4c 24 08 7c f0 c3 55 8b ec 83 ec 1c } //3
		$a_01_2 = {8d 45 d8 c7 45 d8 4f 70 65 6e 50 } //1
		$a_01_3 = {40 00 2e 65 78 65 56 50 ff 15 } //1
		$a_01_4 = {40 00 2e 64 6c 6c 56 50 ff 15 } //1
		$a_01_5 = {53 68 80 00 00 00 6a 02 53 6a 01 68 00 00 00 40 50 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}