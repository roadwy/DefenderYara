
rule Trojan_Win32_Encoder_B{
	meta:
		description = "Trojan:Win32/Encoder.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 69 6c 65 57 61 6c 6c 70 61 70 65 72 } //1 TileWallpaper
		$a_00_1 = {38 31 38 32 35 30 39 35 30 38 36 34 30 33 31 37 37 37 30 39 } //2 81825095086403177709
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2) >=3
 
}
rule Trojan_Win32_Encoder_B_2{
	meta:
		description = "Trojan:Win32/Encoder.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 17 00 00 7e 06 c6 45 fb 05 eb 12 90 09 03 00 81 7d } //1
		$a_01_1 = {85 c0 79 05 05 ff 03 00 00 c1 f8 0a 88 45 fb } //1
		$a_03_2 = {8a 07 03 c0 88 07 ff 45 ?? 47 83 c3 04 ff 4d } //1
		$a_03_3 = {7e 04 c6 45 fb 01 90 0a 13 00 81 7d ?? 00 04 00 00 7d 0a 83 7d ?? 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}