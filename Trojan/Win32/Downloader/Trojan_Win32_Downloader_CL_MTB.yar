
rule Trojan_Win32_Downloader_CL_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {81 7d f8 ff af 00 00 77 2c 8b 55 08 8b 45 f8 01 d0 0f b6 08 8b 45 f8 83 e0 1f 0f b6 44 05 d8 89 c3 8b 55 0c 8b 45 f8 01 d0 31 d9 89 ca 88 10 83 45 f8 01 eb cb } //02 00 
		$a_03_1 = {01 d0 8b 50 04 8b 00 89 cf 31 c7 89 bd 90 01 04 31 d3 89 9d 90 01 04 8b 45 e4 8b 9d 90 01 04 8b b5 90 01 04 89 9c c5 90 01 04 89 b4 c5 90 01 04 83 45 e4 01 eb 9b 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}