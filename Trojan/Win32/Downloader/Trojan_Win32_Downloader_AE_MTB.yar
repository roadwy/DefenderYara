
rule Trojan_Win32_Downloader_AE_MTB{
	meta:
		description = "Trojan:Win32/Downloader.AE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 51 9b 2c 4d 2b f0 8b 18 33 d1 33 da 81 c1 dc 95 1d 00 89 18 83 c0 04 8d 1c 06 3b df 76 e8 } //01 00 
		$a_01_1 = {8a c8 80 c1 41 88 4c 04 16 40 83 f8 1a 72 f1 } //00 00 
	condition:
		any of ($a_*)
 
}