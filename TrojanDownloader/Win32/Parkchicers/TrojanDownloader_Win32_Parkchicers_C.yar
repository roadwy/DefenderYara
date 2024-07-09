
rule TrojanDownloader_Win32_Parkchicers_C{
	meta:
		description = "TrojanDownloader:Win32/Parkchicers.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 74 69 6f 6e 20 44 6f 77 6e 6c 6f 61 64 52 61 6e 64 6f 6d 55 72 6c 46 69 6c 65 28 29 20 53 54 41 52 54 } //1 function DownloadRandomUrlFile() START
		$a_03_1 = {76 44 66 89 44 24 04 66 bb 01 00 8b c5 e8 ?? ?? ?? ?? 0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 3c 96 66 05 75 45 8b f0 43 66 ff 4c 24 04 75 c5 } //1
		$a_03_2 = {66 ba 13 74 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}