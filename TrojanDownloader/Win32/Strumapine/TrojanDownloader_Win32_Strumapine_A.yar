
rule TrojanDownloader_Win32_Strumapine_A{
	meta:
		description = "TrojanDownloader:Win32/Strumapine.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {d3 ef 8b cf f6 d1 32 d9 } //1
		$a_01_1 = {8b 04 24 83 c0 05 c3 } //1
		$a_01_2 = {88 14 01 48 83 f8 ff 75 e7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}