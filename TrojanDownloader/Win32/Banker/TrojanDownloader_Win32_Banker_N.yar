
rule TrojanDownloader_Win32_Banker_N{
	meta:
		description = "TrojanDownloader:Win32/Banker.N,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {8b 45 c0 b2 01 e8 90 01 04 90 90 ff 35 90 01 04 ff 35 90 01 04 68 90 01 04 ff 35 90 01 04 8d 45 bc ba 04 00 00 00 e8 90 01 04 8b 45 bc e8 90 01 04 50 8d 45 b8 b9 50 04 43 38 8b 15 ec a0 43 38 e8 90 01 04 8b 45 b8 90 00 } //2
		$a_03_1 = {85 d2 0f 84 c7 00 00 00 85 c9 0f 84 30 fb ff ff 3b 10 0f 84 be 00 00 00 3b 08 74 0e 50 51 e8 90 01 04 5a 58 e9 90 00 } //2
		$a_80_2 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 35 31 30 30 39 38 35 35 2f 6a 75 6c 69 78 2e 78 74 7a } //http://dl.dropbox.com/u/51009855/julix.xtz  3
		$a_80_3 = {33 61 64 33 32 34 2e 65 78 65 } //3ad324.exe  1
		$a_80_4 = {38 30 30 31 73 32 2e 65 78 65 } //8001s2.exe  1
		$a_80_5 = {6c 64 33 38 34 32 2e 65 78 65 } //ld3842.exe  1
		$a_80_6 = {74 65 78 74 2f 68 74 6d 6c 2c 20 2a 2f 2a } //text/html, */*  1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_80_2  & 1)*3+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}