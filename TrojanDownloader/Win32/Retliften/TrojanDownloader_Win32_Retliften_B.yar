
rule TrojanDownloader_Win32_Retliften_B{
	meta:
		description = "TrojanDownloader:Win32/Retliften.B,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 6e 65 74 66 69 6c 74 65 72 2e 73 79 73 } //10 %s\netfilter.sys
		$a_01_1 = {63 2e 78 61 6c 6d } //1 c.xalm
		$a_01_2 = {63 6f 6e 66 69 67 75 72 65 2e 78 61 6c 6d } //1 configure.xalm
		$a_01_3 = {72 65 67 69 6e 69 00 } //10
		$a_01_4 = {68 74 74 70 3a 2f 2f 34 35 2e 31 31 33 2e 32 30 32 2e 31 38 30 } //10 http://45.113.202.180
		$a_01_5 = {68 74 74 70 3a 2f 2f 31 31 30 2e 34 32 2e 34 2e 31 38 30 } //10 http://110.42.4.180
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=31
 
}