
rule Trojan_Win32_Yakes_DSK_MTB{
	meta:
		description = "Trojan:Win32/Yakes.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b6 d0 0f b6 f1 0f af d6 a0 90 01 04 88 d1 0f b6 d0 88 0c 15 90 01 04 a0 90 01 04 04 01 a2 90 01 04 eb 90 09 0b 00 a0 90 01 04 8a 0d 90 00 } //01 00 
		$a_02_1 = {83 c4 08 8b 15 90 01 04 83 c2 04 89 15 90 01 04 b8 6f 00 00 00 85 c0 0f 85 90 00 } //01 00 
		$a_02_2 = {8b 08 33 0d 90 01 04 8b 15 90 01 04 89 0a 8b e5 5d c3 90 09 05 00 a1 90 00 } //02 00 
		$a_02_3 = {03 c2 89 85 90 01 01 fd ff ff 8b 8d 90 01 01 fc ff ff 0f af 4d 10 6b c9 28 89 8d 90 09 14 00 0f b7 05 90 01 04 0f af 85 90 01 01 fd ff ff 03 85 90 01 01 fd ff ff 90 00 } //02 00 
		$a_00_4 = {0f b6 32 88 d9 d3 fe 89 75 fc 8a 4d fc 88 08 88 f9 88 d8 d2 e0 00 c7 88 3a } //00 00 
	condition:
		any of ($a_*)
 
}