
rule TrojanDownloader_Win32_Thamcower_B{
	meta:
		description = "TrojanDownloader:Win32/Thamcower.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 00 61 00 69 00 78 00 61 00 6e 00 64 00 6f 00 34 00 6c 00 69 00 6e 00 6b 00 } //1 baixando4link
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00 } //1
		$a_01_2 = {63 6f 70 61 64 61 61 66 72 69 63 61 00 } //1
		$a_01_3 = {63 68 75 70 61 61 6e 6d 61 72 61 00 } //1 档灵慡浮牡a
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}