
rule Trojan_Win32_Downloader_CB_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 5f 5a 87 68 8a f7 f6 d1 fe c1 66 f7 d2 f6 d1 32 d9 c0 ea 08 89 04 0c 81 ed 04 00 00 00 8b 54 25 00 3b ff f8 33 d3 0f ca 66 81 fb 35 64 81 f2 96 05 1d 48 f9 c1 c2 02 4a 33 da 03 f2 e9 } //01 00 
		$a_01_1 = {2d 36 17 3f 65 f5 f9 f7 d0 d1 c0 e9 } //00 00 
	condition:
		any of ($a_*)
 
}