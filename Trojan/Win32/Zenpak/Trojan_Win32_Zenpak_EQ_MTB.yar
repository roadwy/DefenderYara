
rule Trojan_Win32_Zenpak_EQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 33 39 2e 32 32 34 2e 31 33 2e 31 38 34 2f 6a 7a 71 2f 62 72 69 61 6e 2e 6a 70 67 } //02 00  139.224.13.184/jzq/brian.jpg
		$a_01_1 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 62 72 69 61 6e 2e 6a 70 67 } //02 00  Users\Public\Documents\brian.jpg
		$a_01_2 = {34 2d 32 37 2e 6f 73 73 2d 63 6e 2d 68 61 6e 67 7a 68 6f 75 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d } //02 00  4-27.oss-cn-hangzhou.aliyuncs.com
		$a_01_3 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6d 64 2e 6a 70 67 } //00 00  Users\Public\Documents\md.jpg
	condition:
		any of ($a_*)
 
}