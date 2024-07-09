
rule TrojanDownloader_Win32_Small_AABH{
	meta:
		description = "TrojanDownloader:Win32/Small.AABH,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 [0-05] 6a 00 6a 00 e8 ?? 00 00 00 83 c4 04 eb 1c 83 7d 0c 00 75 16 ff 35 ?? ?? 00 10 e8 ?? 00 00 00 ff 35 ?? ?? 00 10 } //5
		$a_02_1 = {64 61 69 6c 75 70 [0-03] 6c 61 6e [0-03] 75 6e 6b 6e 6f 77 00 } //2
		$a_00_2 = {76 65 72 3d 25 6c 75 26 75 69 64 3d 25 6c 75 26 63 6f 6e 6e 3d 25 73 26 6f 73 3d 25 73 26 73 6f 63 6b 73 3d 25 6c 75 26 69 70 3d 25 73 } //1 ver=%lu&uid=%lu&conn=%s&os=%s&socks=%lu&ip=%s
		$a_00_3 = {2f 67 65 74 2e 63 67 69 3f 64 61 74 61 3d } //1 /get.cgi?data=
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=8
 
}