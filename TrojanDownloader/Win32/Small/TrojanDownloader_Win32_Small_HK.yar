
rule TrojanDownloader_Win32_Small_HK{
	meta:
		description = "TrojanDownloader:Win32/Small.HK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 7a 74 2e 61 00 } //1
		$a_01_1 = {73 70 3f 75 73 00 } //1 灳甿s
		$a_01_2 = {65 72 6e 61 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}