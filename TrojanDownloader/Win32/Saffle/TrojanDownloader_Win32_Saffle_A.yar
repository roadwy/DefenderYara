
rule TrojanDownloader_Win32_Saffle_A{
	meta:
		description = "TrojanDownloader:Win32/Saffle.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 d0 07 00 00 ff 15 90 01 04 ff 15 90 02 20 3d e8 03 00 00 7c 26 3d d0 07 00 00 7d 1f 90 00 } //1
		$a_08_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_08_2 = {25 73 5c 68 6f 73 74 73 2e 74 78 74 } //1 %s\hosts.txt
		$a_03_3 = {2b c2 3d e8 03 00 00 7c 26 3d d0 07 00 00 7d 1f 6a ff 6a 00 6a 00 ff 15 90 01 02 40 00 85 c0 75 0f 90 00 } //3
	condition:
		((#a_02_0  & 1)*1+(#a_08_1  & 1)*1+(#a_08_2  & 1)*1+(#a_03_3  & 1)*3) >=3
 
}