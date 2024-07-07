
rule TrojanDownloader_Win32_Adload_DS_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 14 8a 02 88 45 fc 8b 4d 14 83 c1 01 89 4d 14 ba 90 01 03 00 03 55 08 8b 45 0c 03 45 08 8b 0d 90 01 03 00 8b 35 90 01 03 00 8a 14 32 88 14 08 8b 45 0c 03 45 08 8b 0d 90 01 03 00 8a 14 08 32 55 fc 8b 45 0c 03 45 08 8b 0d 90 01 03 00 88 14 08 8b 55 08 83 c2 01 89 55 08 90 00 } //1
		$a_03_1 = {83 3c 31 ff 75 15 ba 90 01 03 00 c6 42 0a 90 90 a1 90 01 03 00 c7 04 30 55 8b ec 6a 90 00 } //1
		$a_01_2 = {57 cc b9 0f 00 00 00 33 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}