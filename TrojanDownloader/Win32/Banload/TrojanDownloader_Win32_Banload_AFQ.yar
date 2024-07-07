
rule TrojanDownloader_Win32_Banload_AFQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AFQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 88 08 80 00 00 8d 55 d0 52 8d 45 88 50 ff 15 dc 10 40 00 0f bf c8 85 c9 74 04 eb 7d eb 12 c7 45 fc 08 00 00 00 } //2
		$a_03_1 = {ff 15 7c 10 40 00 dd 5d a0 8d 4d b8 ff 15 10 10 40 00 c7 45 fc 08 00 00 00 68 90 01 02 40 00 8b 55 cc 52 ff 15 2c 10 40 00 90 00 } //1
		$a_01_2 = {6c 00 69 00 62 00 6d 00 79 00 73 00 71 00 6c 00 34 00 31 00 2e 00 64 00 6c 00 6c 00 } //1 libmysql41.dll
		$a_03_3 = {2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 90 02 10 2e 63 73 73 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}