
rule Trojan_Win32_WebToos_B{
	meta:
		description = "Trojan:Win32/WebToos.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 57 65 62 54 6f 6f 73 } //1 圀扥潔獯
		$a_01_1 = {00 49 45 63 74 72 6c 2e 6c 6f 67 00 } //1
		$a_01_2 = {4e 65 77 20 43 49 45 54 68 72 65 61 64 45 78 2e 2e 2e } //1 New CIEThreadEx...
		$a_01_3 = {4f 6e 43 6c 69 63 6b 3a 20 25 73 2d 2d 3e 25 73 } //1 OnClick: %s-->%s
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 56 65 72 73 69 6f 6e 20 56 65 63 74 6f 72 } //1 SOFTWARE\Microsoft\Internet Explorer\Version Vector
		$a_03_5 = {5c 49 45 43 74 72 6c 5c 90 02 08 5c 49 45 43 74 72 6c 2e 70 64 62 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}