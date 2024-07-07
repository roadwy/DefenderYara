
rule TrojanDownloader_Win32_Dold_C{
	meta:
		description = "TrojanDownloader:Win32/Dold.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {e9 3e e2 f9 ff eb e8 5f 5e 5b 8b e5 5d c3 00 ff ff ff ff 06 00 00 00 49 26 43 48 4b 3d } //5
		$a_03_1 = {83 7e 1c 00 74 53 6a 06 6a 01 6a 02 e8 90 01 04 89 46 08 66 c7 46 0c 02 00 0f b7 45 fc 90 00 } //2
		$a_01_2 = {8b 45 fc 80 78 5b 00 74 3d 8b 45 fc 8b 40 44 80 b8 73 02 00 00 01 74 09 80 3d 5c 16 47 00 01 75 1e } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}