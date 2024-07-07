
rule TrojanProxy_Win32_Tinxy_G{
	meta:
		description = "TrojanProxy:Win32/Tinxy.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 63 65 73 73 2d 63 6c 69 63 6b 73 00 } //1
		$a_00_1 = {47 45 54 20 2f 73 65 61 72 63 68 2e 70 68 70 3f 70 3d 25 30 34 64 26 73 3d 25 73 26 76 3d 25 73 26 71 3d 25 73 } //1 GET /search.php?p=%04d&s=%s&v=%s&q=%s
		$a_03_2 = {05 00 ff ff ff 90 01 03 ff 15 90 01 09 68 00 01 00 00 90 01 02 ff 15 90 00 } //1
		$a_03_3 = {85 db 75 07 be 90 01 04 eb 1b 83 fb 01 75 07 be 90 01 04 eb 0f 83 fb 02 be 90 01 04 74 05 be 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}