
rule TrojanDownloader_Win32_Small_CM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 cb f7 d1 03 cb 03 0a 89 08 8b c2 3b 45 f4 } //2
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 2f 25 73 } //1 http://%s:%d/%s/%s
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}