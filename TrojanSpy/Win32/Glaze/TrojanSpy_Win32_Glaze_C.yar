
rule TrojanSpy_Win32_Glaze_C{
	meta:
		description = "TrojanSpy:Win32/Glaze.C,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 f2 90 01 01 88 11 41 4f 75 f4 90 00 } //05 00 
		$a_03_1 = {8a 08 84 c9 74 08 80 f1 90 01 01 88 08 40 eb f2 90 00 } //0a 00 
		$a_03_2 = {66 3d 15 00 0f 85 90 01 01 00 00 00 53 ff 76 04 ff 15 90 01 02 00 10 80 a5 90 01 01 ff ff ff 00 6a 31 8b d8 59 33 c0 8d bd 90 01 01 ff ff ff f3 ab 66 ab aa 8d 85 90 01 01 ff ff ff 90 00 } //01 00 
		$a_01_3 = {61 6c 6f 67 2e 74 78 74 00 } //01 00 
		$a_01_4 = {57 53 50 53 74 61 72 74 75 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}