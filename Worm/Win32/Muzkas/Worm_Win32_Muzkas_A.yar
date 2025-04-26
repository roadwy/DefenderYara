
rule Worm_Win32_Muzkas_A{
	meta:
		description = "Worm:Win32/Muzkas.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b f0 8b d3 8b c6 8b 08 ff 51 08 c6 46 3f 28 } //2
		$a_01_1 = {32 1c 08 8b 4c 24 04 88 1c 31 46 4a 75 b4 } //2
		$a_03_2 = {ff 75 fc ff 75 f8 e8 ?? ?? ?? ff 8b d8 68 00 01 00 00 8d 85 f8 fe ff ff 50 53 e8 ?? ?? ?? ff 84 c0 74 2e } //2
		$a_01_3 = {6b 75 6c 6c 5f 6e 61 6d 65 3d } //1 kull_name=
		$a_01_4 = {53 75 6e 4a 61 76 61 55 70 64 61 74 65 53 63 68 65 64 2e 6c 6e 6b } //1 SunJavaUpdateSched.lnk
		$a_01_5 = {6a 61 76 61 73 63 68 65 64 73 } //1 javascheds
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}