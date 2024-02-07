
rule TrojanDownloader_Win32_Small_AHV{
	meta:
		description = "TrojanDownloader:Win32/Small.AHV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 6b 75 77 6f 5f 6a 6d 39 2e 65 78 65 } //01 00  C:\kuwo_jm9.exe
		$a_01_1 = {64 6f 77 6e 2e 6b 75 77 6f 2e 63 6e 2f 6d 62 6f 78 2f 6b 75 77 6f 5f 6a 6d 39 2e 65 78 65 } //01 00  down.kuwo.cn/mbox/kuwo_jm9.exe
		$a_01_2 = {43 00 3a 00 5c 00 6b 00 75 00 77 00 6f 00 5f 00 6a 00 6d 00 39 00 2e 00 65 00 78 00 65 00 } //01 00  C:\kuwo_jm9.exe
		$a_01_3 = {64 00 6f 00 77 00 6e 00 2e 00 6b 00 75 00 77 00 6f 00 2e 00 63 00 6e 00 2f 00 6d 00 62 00 6f 00 78 00 2f 00 6b 00 75 00 77 00 6f 00 5f 00 6a 00 6d 00 39 00 2e 00 65 00 78 00 65 00 } //00 00  down.kuwo.cn/mbox/kuwo_jm9.exe
	condition:
		any of ($a_*)
 
}