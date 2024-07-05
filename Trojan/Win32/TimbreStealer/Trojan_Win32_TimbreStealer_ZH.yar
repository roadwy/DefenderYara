
rule Trojan_Win32_TimbreStealer_ZH{
	meta:
		description = "Trojan:Win32/TimbreStealer.ZH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 01 00 00 50 90 02 20 8d 44 24 90 01 01 50 e8 90 01 04 83 c4 0c 33 ff 33 c0 90 00 } //01 00 
		$a_03_1 = {40 3d 00 01 00 00 72 f4 90 02 08 33 f6 90 02 04 8a 54 34 90 01 01 8b c6 83 e0 03 0f b6 ca 0f b6 80 90 00 } //01 00 
		$a_03_2 = {03 c7 03 c8 0f b6 f9 8a 44 3c 90 01 01 88 44 34 90 01 01 46 88 54 3c 90 01 01 81 fe 00 01 00 00 72 d1 90 00 } //01 00 
		$a_01_3 = {8b 46 3c 85 c0 74 2f 8b 54 30 7c 85 d2 74 27 8b 44 30 78 85 c0 74 1f 8d 4c 24 1c 51 52 8d 14 30 8b ce e8 } //00 00 
	condition:
		any of ($a_*)
 
}