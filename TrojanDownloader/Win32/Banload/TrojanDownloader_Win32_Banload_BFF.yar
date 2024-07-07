
rule TrojanDownloader_Win32_Banload_BFF{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 5c 38 ff 33 5d 90 01 01 3b 5d 90 01 01 7f 0b 81 c3 ff 00 00 00 2b 5d 90 01 01 eb 03 90 00 } //1
		$a_03_1 = {8b 45 08 81 78 fc f4 01 00 00 0f 8d 90 01 04 a1 90 01 04 8b 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}