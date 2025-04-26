
rule TrojanDownloader_Win32_Hupigon_A{
	meta:
		description = "TrojanDownloader:Win32/Hupigon.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 64 00 6c 00 6c 00 2c 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //1 .dll,download
		$a_01_1 = {5c 00 76 00 62 00 61 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 \vbame.dll
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 78 62 61 74 74 65 72 79 2e 63 6f 6d } //1 http://www.sxbattery.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}