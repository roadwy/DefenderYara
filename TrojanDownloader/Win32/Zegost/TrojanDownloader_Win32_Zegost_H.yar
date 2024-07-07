
rule TrojanDownloader_Win32_Zegost_H{
	meta:
		description = "TrojanDownloader:Win32/Zegost.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 11 0f be 45 f0 2b d0 8b 4d fc 03 4d f8 88 11 8b 55 fc 03 55 f8 0f be 02 0f be 4d ec 33 c1 8b 55 fc 03 55 f8 88 02 e8 90 01 04 eb a6 90 00 } //1
		$a_03_1 = {fe ff ff 4e c6 85 90 01 01 fe ff ff 65 c6 85 90 01 01 fe ff ff 74 c6 85 90 01 01 fe ff ff 53 c6 85 90 01 01 fe ff ff 79 c6 85 90 01 01 fe ff ff 73 c6 85 90 01 01 fe ff ff 74 c6 85 90 01 01 fe ff ff 32 c6 85 90 01 01 fe ff ff 2e c6 85 90 01 01 fe ff ff 64 c6 85 90 01 01 fe ff ff 6c c6 85 90 01 01 fe ff ff 6c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}