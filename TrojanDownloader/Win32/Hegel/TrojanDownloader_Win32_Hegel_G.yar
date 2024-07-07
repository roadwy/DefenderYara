
rule TrojanDownloader_Win32_Hegel_G{
	meta:
		description = "TrojanDownloader:Win32/Hegel.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 69 64 3d 25 73 25 73 90 02 10 26 73 74 61 74 75 73 3d 67 6f 6f 64 90 00 } //1
		$a_03_1 = {83 3f ff 74 08 81 fb 00 00 05 00 75 90 01 01 ff 37 ff 15 90 01 04 57 ff d6 59 81 fb 00 04 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}