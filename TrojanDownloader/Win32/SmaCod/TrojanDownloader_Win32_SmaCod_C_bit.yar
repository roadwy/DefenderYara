
rule TrojanDownloader_Win32_SmaCod_C_bit{
	meta:
		description = "TrojanDownloader:Win32/SmaCod.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {51 6a 00 ff 15 90 01 04 89 45 90 01 01 8d 55 90 01 01 52 8b 45 90 01 01 2b 45 90 01 01 50 8b 4d 90 01 01 03 4d 90 01 01 51 8b 55 90 01 01 52 ff 15 90 00 } //5
		$a_01_1 = {2f 63 6f 64 } //5 /cod
		$a_01_2 = {8b 55 d8 89 55 cc 83 7d cc 00 74 03 ff 55 cc } //1
		$a_03_3 = {89 45 fc 85 c0 75 08 6a ff ff 15 90 01 04 8b 45 fc ff d0 90 00 } //1
		$a_03_4 = {83 7d fc 00 74 90 01 01 ff 55 90 01 01 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=11
 
}