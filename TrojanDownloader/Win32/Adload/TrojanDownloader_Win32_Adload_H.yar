
rule TrojanDownloader_Win32_Adload_H{
	meta:
		description = "TrojanDownloader:Win32/Adload.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 41 51 8d 55 90 01 01 8b cc 89 a5 90 01 01 ff ff ff 52 e8 90 01 02 00 00 8b ce e8 90 01 02 ff ff 8b 4d 90 01 01 8d 85 90 01 02 ff ff 6a 01 50 6a 00 51 68 90 01 02 40 00 6a 00 ff 15 90 01 02 40 00 8d 4d 90 01 01 c6 45 fc 3a 90 00 } //1
		$a_03_1 = {c6 45 fc 9b e8 90 01 02 ff ff 6a 2f 8d 8d 90 01 01 ff ff ff c6 45 fc 9d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}