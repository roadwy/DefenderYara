
rule TrojanDownloader_Win32_Adload_DV_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DV!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 70 68 70 3f 70 3d 73 65 76 65 6e 7a 69 70 26 74 69 64 3d } //2 .php?p=sevenzip&tid=
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 00 57 69 6e 64 6f 77 73 20 52 65 66 72 65 73 68 00 } //2
		$a_01_2 = {00 2f 53 49 4c 45 4e 54 00 67 65 74 00 } //1
		$a_01_3 = {00 64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 00 } //1 搀睯汮慯彤畱敩t
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}