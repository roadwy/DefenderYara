
rule Worm_Win32_Dorpiex_A{
	meta:
		description = "Worm:Win32/Dorpiex.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {26 63 6c 69 65 6e 74 3d 77 65 62 5f 6d 65 73 73 65 6e 67 65 72 26 5f 5f 75 73 65 72 3d 25 73 26 5f 5f 61 3d 31 } //10 &client=web_messenger&__user=%s&__a=1
		$a_03_1 = {8b f8 85 ff 0f 84 ?? ?? 00 00 81 3f 31 52 44 4c 53 55 0f 85 ?? ?? 00 00 8b 44 24 ?? 83 f8 0c } //1
		$a_03_2 = {81 38 31 52 44 4c 0f 85 ?? ?? 00 00 83 7d f4 ?? 73 05 e9 ?? ?? 00 00 8b 4d ?? 83 e9 0c } //1
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}