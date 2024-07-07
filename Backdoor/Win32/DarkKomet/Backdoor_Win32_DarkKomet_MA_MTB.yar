
rule Backdoor_Win32_DarkKomet_MA_MTB{
	meta:
		description = "Backdoor:Win32/DarkKomet.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 5d 08 b8 4d 5a 00 00 66 39 03 74 90 01 01 33 c0 eb 90 01 01 8b 43 3c 81 3c 18 50 45 00 00 75 90 01 01 8b 44 18 78 83 65 08 00 56 03 c3 8b 70 20 8b 48 18 57 8b 78 1c 03 f3 03 fb 89 4d fc 85 c9 74 90 00 } //1
		$a_03_1 = {33 c1 8b c8 c1 e1 18 c1 f9 1f 81 e1 90 01 04 8b f0 c1 e6 1f c1 fe 1f 81 e6 90 01 04 33 ce 8b f0 c1 e6 1d c1 fe 1f 81 e6 90 01 04 33 ce 8b f0 c1 e6 19 c1 fe 1f 81 e6 90 01 04 33 ce 8b f0 c1 e6 1a c1 fe 1f 81 e6 90 01 04 33 ce 90 00 } //1
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}