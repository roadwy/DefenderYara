
rule TrojanDownloader_Win32_Small_AGT{
	meta:
		description = "TrojanDownloader:Win32/Small.AGT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 6e 69 75 64 6f 75 64 6f 75 2e 63 6f 6d 2f 77 65 62 2f 64 6f 77 6e 6c 6f 61 64 2f } //1 .niudoudou.com/web/download/
		$a_01_1 = {53 53 4c 44 65 73 6b 54 6f 70 } //1 SSLDeskTop
		$a_01_2 = {49 45 46 72 61 6d 65 } //1 IEFrame
		$a_01_3 = {25 73 63 6c 69 63 6b 5f 6c 6f 67 2e 61 73 70 3f 61 64 5f 75 72 6c 3d 25 73 } //1 %sclick_log.asp?ad_url=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}