
rule TrojanDownloader_Win32_Banload_ABQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ABQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {63 6f 6e 66 69 67 2d 63 61 63 68 65 2e 63 6f 6d 2f 69 65 90 02 10 75 74 6f 43 6f 6e 66 69 67 55 52 4c 90 00 } //1
		$a_01_1 = {00 74 69 70 6f 3d } //1 琀灩㵯
		$a_00_2 = {77 77 77 2e 65 6d 6f 74 69 6f 6e 76 69 72 74 75 61 6c 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 } //1 www.emotionvirtual.com/index.php
		$a_02_3 = {2e 00 63 00 6f 00 6d 00 2f 00 42 00 72 00 46 00 6c 00 61 00 73 00 68 00 2f 00 54 00 65 00 41 00 64 00 6f 00 72 00 6f 00 2f 00 90 02 0a 2e 00 73 00 77 00 66 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}