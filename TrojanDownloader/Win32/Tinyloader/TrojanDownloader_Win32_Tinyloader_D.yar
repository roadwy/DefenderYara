
rule TrojanDownloader_Win32_Tinyloader_D{
	meta:
		description = "TrojanDownloader:Win32/Tinyloader.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 7c 03 ff c3 74 02 eb 18 8b 45 00 83 c0 0c ff d0 } //1
		$a_01_1 = {e8 08 00 00 00 63 6f 6e 6e 65 63 74 00 ff 75 48 ff 55 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}