
rule TrojanDownloader_Win32_Allaple_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Allaple.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 } //10 FastMM Borland
		$a_03_1 = {6a ff 6a 00 e8 ?? ?? ?? ff 8b d8 85 db 74 0c e8 ?? ?? ?? ff 3d b7 00 00 00 75 0d 53 e8 } //10
		$a_01_2 = {70 69 63 73 2f 64 65 66 61 75 6c 74 2f 69 72 73 5f } //1 pics/default/irs_
		$a_01_3 = {65 6d 61 69 6c 5f 64 6f 77 6e 6c 6f 61 64 65 72 } //1 email_downloader
		$a_01_4 = {57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 65 6e 3b 29 20 47 65 63 6b 6f 2f } //1 Windows NT 5.1; en;) Gecko/
		$a_01_5 = {69 72 73 5f 65 66 69 6c 6c 2e 70 68 70 00 55 8b } //3
		$a_03_6 = {53 79 73 74 65 6d 52 6f 6f 74 00 00 65 78 70 6c 6f 72 65 72 20 68 74 74 70 3a 2f 2f [0-30] 2e 70 64 66 } //3
		$a_01_7 = {2e 70 64 66 00 00 ff ff ff ff 0c 00 00 00 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 } //3
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3+(#a_03_6  & 1)*3+(#a_01_7  & 1)*3) >=29
 
}