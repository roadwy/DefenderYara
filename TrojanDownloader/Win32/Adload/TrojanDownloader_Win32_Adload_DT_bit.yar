
rule TrojanDownloader_Win32_Adload_DT_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DT!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6c 69 70 2e 73 65 61 74 6f 6d 61 74 6f 65 73 2e 62 69 64 2f 73 74 61 74 73 2e 70 68 70 3f 62 75 3d } //2 slip.seatomatoes.bid/stats.php?bu=
		$a_01_1 = {00 61 72 5f 75 72 6c 00 61 72 5f 73 69 6c 65 6e 74 00 61 72 5f 62 75 6e 64 6c 65 00 61 72 5f 6d 65 73 73 61 67 65 00 } //2
		$a_01_2 = {00 2f 53 49 4c 45 4e 54 00 67 65 74 00 } //1
		$a_01_3 = {00 64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 00 } //1 搀睯汮慯彤畱敩t
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}