
rule TrojanDownloader_Win32_Cbeplay_M{
	meta:
		description = "TrojanDownloader:Win32/Cbeplay.M,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {83 bf 10 04 00 00 00 8d b7 14 04 00 00 } //2
		$a_03_1 = {ff b7 08 02 00 00 8d 44 ?? ?? 50 68 ?? ?? 40 00 8d 87 04 01 00 00 68 04 01 00 00 50 e8 ?? ?? 00 00 83 c4 14 } //1
		$a_03_2 = {8b 83 14 0c 00 00 [0-04] 83 bb 18 0c 00 00 00 74 ?? 50 68 08 01 00 00 e8 } //2
		$a_01_3 = {b9 4d 5a 00 00 8b 45 08 66 39 08 } //1
		$a_01_4 = {25 73 26 63 74 6c 3d 25 64 26 64 61 74 61 3d 25 73 } //2 %s&ctl=%d&data=%s
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=5
 
}