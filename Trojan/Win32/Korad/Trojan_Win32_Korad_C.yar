
rule Trojan_Win32_Korad_C{
	meta:
		description = "Trojan:Win32/Korad.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {ff ff 27 c6 85 90 01 02 ff ff 6c c6 85 90 01 02 ff ff 6a c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 65 90 00 } //05 00 
		$a_03_1 = {27 6c 6a 6f c7 90 01 05 65 3e 35 00 e8 90 00 } //05 00 
		$a_01_2 = {0f b6 06 88 07 0f b6 4e 01 88 4f 01 0f b6 56 02 88 57 02 0f b6 46 03 88 47 03 0f b6 4e 04 8d 47 04 88 08 0f b6 56 05 88 57 05 0f b6 4e 06 88 4f 06 } //05 00 
		$a_01_3 = {0f b6 0e 88 4f fe 0f b6 56 01 8d 47 fe 88 57 ff 0f b6 4e 02 88 0f 0f b6 56 03 88 57 01 0f b6 56 04 8d 4f 02 88 11 0f b6 56 05 88 57 03 0f b6 56 06 } //01 00 
		$a_01_4 = {63 3a 5c 00 8b } //01 00 
		$a_01_5 = {63 3a 5c 00 e8 } //05 00 
		$a_01_6 = {be 5a 00 00 00 f7 fe 8b 45 08 8d 34 01 0f be 04 33 bb 5a 00 00 00 41 8b fa 2b c7 83 c0 37 99 f7 fb 80 c2 23 3b 4d f8 88 16 7c ce } //00 00 
	condition:
		any of ($a_*)
 
}