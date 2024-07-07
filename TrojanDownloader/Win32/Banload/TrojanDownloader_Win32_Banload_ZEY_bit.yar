
rule TrojanDownloader_Win32_Banload_ZEY_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEY!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 00 70 00 30 00 39 00 35 00 36 00 34 00 35 00 37 00 } //1 Up0956457
		$a_01_1 = {5c 00 48 00 65 00 79 00 73 00 6f 00 75 00 6c 00 2e 00 65 00 62 00 61 00 79 00 } //1 \Heysoul.ebay
		$a_01_2 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 } //1
		$a_03_3 = {83 c4 88 53 33 d2 89 55 90 90 89 55 8c 89 55 88 89 55 fc 33 c0 55 68 90 01 04 64 ff 30 64 89 20 8d 45 fc ba 90 01 04 e8 90 01 04 6a 32 8d 45 96 50 e8 90 01 04 0f b7 c0 50 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}