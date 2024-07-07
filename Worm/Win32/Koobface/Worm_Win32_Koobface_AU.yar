
rule Worm_Win32_Koobface_AU{
	meta:
		description = "Worm:Win32/Koobface.AU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 61 63 74 69 6f 6e 3d 74 77 72 65 67 26 6d 6f 64 65 3d 72 65 73 26 } //1 %s?action=twreg&mode=res&
		$a_01_1 = {2f 2e 73 79 73 2e 70 68 70 00 } //1
		$a_03_2 = {68 88 13 00 00 c6 45 fc 0f ff d7 53 8d 85 90 01 04 50 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}