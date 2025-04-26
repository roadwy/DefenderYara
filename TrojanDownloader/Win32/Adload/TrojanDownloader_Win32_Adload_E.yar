
rule TrojanDownloader_Win32_Adload_E{
	meta:
		description = "TrojanDownloader:Win32/Adload.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 2e 78 69 61 6c 64 2e 63 6f 6d } //1 down.xiald.com
		$a_01_1 = {64 6f 77 6e 63 64 6e 2e 78 69 61 6c 64 2e 63 6f 6d } //1 downcdn.xiald.com
		$a_01_2 = {74 6a 76 31 2e 78 69 61 6c 64 2e 63 6f 6d } //1 tjv1.xiald.com
		$a_01_3 = {3a 5c 58 69 61 5a 61 69 51 69 5c 70 64 62 6d 61 70 5c 57 61 6e 4e 65 6e 67 5c 49 6e 73 74 61 6c 6c 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}