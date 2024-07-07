
rule TrojanDownloader_Win32_Small_AIA{
	meta:
		description = "TrojanDownloader:Win32/Small.AIA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 47 6f 6f 67 6c 65 25 63 25 63 2e 65 78 65 } //1 %s\Google%c%c.exe
		$a_01_1 = {21 40 23 24 72 23 40 25 40 23 24 40 23 } //1 !@#$r#@%@#$@#
		$a_03_2 = {83 c9 ff 33 c0 c6 90 02 03 44 c6 90 02 03 65 c6 90 02 03 6e c6 90 02 03 67 90 00 } //1
		$a_01_3 = {b0 0a c6 44 24 1c 41 c6 44 24 1f 65 c6 44 24 20 70 c6 44 24 21 74 c6 44 24 22 3a c6 44 24 23 20 c6 44 24 25 2f 88 4c 24 27 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}