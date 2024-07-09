
rule TrojanDownloader_Win32_SmaCod_A_bit{
	meta:
		description = "TrojanDownloader:Win32/SmaCod.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {77 77 77 2e 73 74 61 72 2d 73 6b 69 6e 2e 63 6f 6d 00 00 00 2f 62 6f 61 72 64 2f ?? ?? 2f 63 6f 64 } //2
		$a_03_1 = {75 74 69 6c [0-10] 6d 61 6c 6c 2e 63 6f 6d [0-20] 2f 62 62 73 2f 61 [0-05] 64 5f ?? ?? 2f [0-05] 63 6f 64 } //2
		$a_01_2 = {8b 55 d8 89 55 cc 83 7d cc 00 74 03 ff 55 cc } //1
		$a_03_3 = {89 45 fc 85 c0 75 08 6a ff ff 15 ?? ?? ?? ?? 8b 45 fc ff d0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}