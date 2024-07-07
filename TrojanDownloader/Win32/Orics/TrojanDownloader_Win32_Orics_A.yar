
rule TrojanDownloader_Win32_Orics_A{
	meta:
		description = "TrojanDownloader:Win32/Orics.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6b c9 3c 69 c9 e8 03 00 00 51 ff 15 90 01 03 00 90 00 } //1
		$a_00_1 = {00 53 76 68 73 74 00 00 00 53 77 68 73 74 } //1
		$a_00_2 = {50 4f 53 54 20 2f 62 6e 2f 6c 69 73 74 65 6e 65 72 2e 70 68 70 } //1 POST /bn/listener.php
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}