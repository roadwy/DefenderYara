
rule TrojanDownloader_Win32_Banload_ST{
	meta:
		description = "TrojanDownloader:Win32/Banload.ST,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 b8 50 6a 00 6a 00 6a 30 6a 00 6a 00 6a 00 8b 45 fc e8 90 01 03 ff 50 6a 00 e8 90 01 03 ff 83 f8 01 90 00 } //3
		$a_01_1 = {50 72 6f 63 65 73 73 53 69 6d 70 6c 65 00 44 6f 77 6e 00 45 78 74 72 61 69 72 } //2 牐捯獥即浩汰e潄湷䔀瑸慲物
		$a_01_2 = {45 44 65 63 6f 6d 70 72 65 73 73 69 6f 6e 45 72 72 6f 72 } //1 EDecompressionError
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}