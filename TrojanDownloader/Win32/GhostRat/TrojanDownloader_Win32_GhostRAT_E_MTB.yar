
rule TrojanDownloader_Win32_GhostRAT_E_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8d 85 f8 fe ff ff 57 50 56 ff 15 90 01 04 8d 45 fc 50 68 3f 00 0f 00 56 68 90 01 04 68 01 00 00 80 ff 15 90 00 } //2
		$a_03_1 = {57 8d 85 f8 fe ff ff 50 6a 01 56 68 90 01 04 ff 75 fc ff 15 90 01 04 ff 75 fc ff 15 90 00 } //2
		$a_03_2 = {83 c4 0c 8d 85 f8 fe ff ff 68 04 01 00 00 50 6a 00 ff 15 90 01 04 8d 45 fc 50 68 3f 00 0f 00 6a 00 68 90 01 04 68 01 00 00 80 ff 15 90 00 } //2
		$a_03_3 = {68 04 01 00 00 8d 85 f8 fe ff ff 50 6a 01 6a 00 68 90 01 04 ff 75 fc ff 15 90 01 04 ff 75 fc ff 15 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=4
 
}