
rule TrojanDownloader_Win32_Camec_E{
	meta:
		description = "TrojanDownloader:Win32/Camec.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 0c 89 5d 88 b8 03 40 00 00 89 45 80 8b 4d 10 89 8d 78 ff ff ff ba 08 40 00 00 89 95 70 ff ff ff } //1
		$a_01_1 = {8b 8d 1c ff ff ff 51 8b 55 08 8b 42 6c 8b 48 04 51 8b 35 } //1
		$a_01_2 = {c7 45 c4 02 00 00 80 8b 46 6c 8b 0e 8d 55 c8 52 8d 50 04 52 8d 55 dc 52 8d 50 10 52 83 c0 0c 50 } //1
		$a_01_3 = {8b 55 28 8b 02 89 85 e0 fe ff ff 89 b5 d8 fe ff ff 8b 47 6c 8b 48 34 89 8d d0 fe ff ff 89 b5 c8 fe ff ff 8b 50 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}