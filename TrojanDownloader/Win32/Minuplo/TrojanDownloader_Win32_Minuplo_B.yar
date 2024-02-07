
rule TrojanDownloader_Win32_Minuplo_B{
	meta:
		description = "TrojanDownloader:Win32/Minuplo.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 73 72 73 73 72 2e 65 78 65 00 } //01 00 
		$a_01_1 = {6d 69 6e 69 75 70 6c 6f 61 64 2e 6e 65 74 2f 69 72 2f 73 31 2e 70 68 70 } //01 00  miniupload.net/ir/s1.php
		$a_01_2 = {6d 69 6e 69 75 70 6c 6f 61 64 2e 6e 65 74 2f 69 72 2f 75 72 6c } //00 00  miniupload.net/ir/url
	condition:
		any of ($a_*)
 
}