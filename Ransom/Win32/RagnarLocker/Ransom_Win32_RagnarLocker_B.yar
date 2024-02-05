
rule Ransom_Win32_RagnarLocker_B{
	meta:
		description = "Ransom:Win32/RagnarLocker.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 8a 9c 35 90 01 04 33 d2 0f b6 cb f7 75 0c 8b 45 08 0f b6 04 02 03 c7 03 c8 0f b6 f9 8a 84 3d 90 01 04 88 84 35 90 01 04 46 88 9c 3d 90 01 04 81 fe 00 01 00 00 72 c3 90 00 } //01 00 
		$a_03_1 = {40 8d 7f 01 0f b6 d0 89 55 90 01 01 8a 8c 15 90 01 04 0f b6 c1 03 c3 0f b6 d8 8a 84 1d 90 01 04 88 84 15 90 01 04 8b 45 90 00 } //01 00 
		$a_03_2 = {0f b6 d1 88 8c 1d 90 01 04 0f b6 8c 05 90 01 04 03 d1 0f b6 ca 0f b6 8c 0d 90 01 04 30 4f ff 83 ee 01 75 af 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}