
rule TrojanDownloader_Win32_Rotbope_A{
	meta:
		description = "TrojanDownloader:Win32/Rotbope.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 6f 62 6f 74 2d 74 61 6f 62 61 6f 2e 70 68 70 00 } //1
		$a_01_1 = {6e 61 76 69 64 61 76 69 64 65 6f } //1 navidavideo
		$a_01_2 = {61 62 63 64 65 66 74 67 65 74 64 77 2e 65 78 65 00 } //1
		$a_01_3 = {61 62 63 2e 72 65 67 00 73 76 63 68 6f 73 74 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}