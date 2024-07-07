
rule TrojanDownloader_Win32_Small_LD{
	meta:
		description = "TrojanDownloader:Win32/Small.LD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 6c 80 7d 08 00 57 74 0d bf 90 01 04 c1 ef 10 c1 e7 10 eb 03 8b 7b 34 90 00 } //1
		$a_03_1 = {53 56 c7 05 90 01 04 c0 66 00 00 c7 05 90 01 04 90 90 5b 00 00 81 05 90 01 04 dc 0f 00 00 c7 05 90 01 04 83 07 00 00 81 05 90 01 04 fc 6e 00 00 c7 05 90 01 04 42 09 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}