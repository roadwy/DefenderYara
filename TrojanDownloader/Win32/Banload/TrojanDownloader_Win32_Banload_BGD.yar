
rule TrojanDownloader_Win32_Banload_BGD{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 59 e8 90 01 03 ff 8d 55 f8 b8 90 01 03 00 e8 90 01 02 ff ff 8d 55 f4 b8 90 01 03 00 e8 90 01 02 ff ff 8d 55 f0 b8 90 01 03 00 e8 90 01 02 ff ff 0f b6 05 90 01 03 00 50 8d 45 c8 50 8d 55 c4 b8 90 01 03 00 e8 90 01 02 ff ff 90 00 } //1
		$a_03_1 = {4e 75 ca 8d 95 6c ff ff ff b8 90 01 03 00 e8 90 01 02 ff ff 8b 8d 6c ff ff ff 8d 45 e8 8b 55 e0 e8 90 01 03 ff b2 01 a1 a0 85 48 00 e8 90 01 03 ff 8b d8 8d 95 68 ff ff ff b8 90 01 03 00 e8 90 01 02 ff ff 8b 95 68 ff ff ff 8b c3 8b 08 ff 51 3c 8d 95 60 ff ff ff b8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}