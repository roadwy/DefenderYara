
rule TrojanDownloader_Win32_Banload_ARJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {54 61 62 4f 72 64 65 72 ?? ?? ?? 54 65 78 74 ?? ?? 68 74 74 70 [0-01] 3a 2f 2f } //1
		$a_03_1 = {ff 84 c0 74 05 e8 ?? ?? ?? ff 68 ?? ?? 00 00 e8 ?? ?? ?? ff 8d 55 e8 8b } //1
		$a_01_2 = {eb 05 bf 01 00 00 00 8b 45 e8 33 db 8a 5c 38 ff 33 5d e4 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03 } //1
		$a_03_3 = {83 c0 50 e8 ?? ?? ?? ff 6a 00 8d 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}