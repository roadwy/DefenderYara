
rule Trojan_Win32_Downloader_CM_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CM!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 c3 e9 dc e7 79 01 c3 81 eb e9 dc e7 79 01 0b } //1
		$a_01_1 = {05 04 00 00 00 33 04 24 31 04 24 33 04 24 5c 39 c2 0f 84 } //1
		$a_01_2 = {81 f1 2a 5f ff 43 01 cb 59 81 eb 04 00 00 00 33 1c 24 31 1c 24 33 1c 24 5c 89 04 24 8f 45 f0 e9 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}