
rule TrojanDownloader_Win32_Small_AIM{
	meta:
		description = "TrojanDownloader:Win32/Small.AIM,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {39 39 39 39 39 39 39 39 39 39 39 39 2e 75 72 6c } //1 999999999999.url
		$a_01_1 = {74 61 7a 62 61 6f 2e 63 6f 6d } //1 tazbao.com
		$a_01_2 = {5c 66 69 65 2e 65 78 65 } //1 \fie.exe
		$a_01_3 = {25 73 5c 47 6f 6f 67 6c 65 25 63 25 63 2e 65 78 65 } //1 %s\Google%c%c.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}