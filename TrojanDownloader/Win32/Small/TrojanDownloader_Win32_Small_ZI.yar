
rule TrojanDownloader_Win32_Small_ZI{
	meta:
		description = "TrojanDownloader:Win32/Small.ZI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 76 68 6f 73 74 2e 65 78 65 00 } //1
		$a_01_1 = {2f 63 72 79 2f } //1 /cry/
		$a_01_2 = {8a 04 0a 2c 7a 88 01 41 4e 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}