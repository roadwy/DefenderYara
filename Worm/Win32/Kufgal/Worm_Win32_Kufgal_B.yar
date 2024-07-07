
rule Worm_Win32_Kufgal_B{
	meta:
		description = "Worm:Win32/Kufgal.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 cf ff 56 e8 90 01 02 ff ff 83 f8 01 1b c0 40 84 c0 0f 84 90 01 01 00 00 00 6a e0 56 e8 90 01 02 ff ff 3d 02 80 00 00 90 00 } //1
		$a_03_1 = {64 ff 30 64 89 20 c7 45 fc ff ff ff ff 6a e0 56 e8 90 01 02 ff ff 3d 02 80 00 00 90 00 } //1
		$a_03_2 = {8b d8 53 e8 90 01 02 ff ff 6a 00 53 68 90 01 04 e8 90 01 02 ff ff 90 00 } //1
		$a_03_3 = {83 c0 14 83 c0 02 50 6a 42 e8 90 01 02 ff ff 8b f0 85 f6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}