
rule Trojan_Win32_Azorult_PVS_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 03 f0 81 e6 ff 00 00 00 81 3d 90 01 04 81 0c 00 00 5b 75 90 09 07 00 0f b6 b0 90 00 } //02 00 
		$a_02_1 = {8b 44 24 10 81 44 24 1c 90 01 04 33 c6 2b e8 ff 4c 24 24 89 44 24 10 0f 85 90 00 } //02 00 
		$a_02_2 = {33 fa 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 90 09 06 00 8b 3d 90 00 } //02 00 
		$a_00_3 = {8a 1c 0b 89 0c 24 8b 4c 24 20 32 1c 39 8b 7c 24 14 8b 0c 24 88 1c 0f } //00 00 
	condition:
		any of ($a_*)
 
}