
rule TrojanDownloader_Win32_Small_SO{
	meta:
		description = "TrojanDownloader:Win32/Small.SO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 68 1a 20 40 00 68 10 20 40 00 6a 00 6a 00 e8 0d 00 00 00 6a 00 e8 00 00 00 00 ff 25 } //1
		$a_03_1 = {6d 73 68 74 61 2e 65 78 65 00 68 74 74 70 3a 2f 2f 90 02 15 2e 63 6e 2f 90 05 05 04 61 2d 7a 5f 2e 70 68 70 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}