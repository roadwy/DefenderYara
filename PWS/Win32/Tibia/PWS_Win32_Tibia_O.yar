
rule PWS_Win32_Tibia_O{
	meta:
		description = "PWS:Win32/Tibia.O,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 43 10 c7 00 54 69 62 00 c7 04 24 ff 00 00 00 e8 ?? ?? 00 00 89 83 9c 00 00 00 c7 83 94 00 00 00 00 00 00 00 c6 00 00 c7 83 98 00 00 00 00 00 00 00 c7 04 24 ff 00 00 00 e8 ?? ?? 00 00 89 43 1c c7 04 24 84 03 00 00 } //1
		$a_01_1 = {c7 00 6c 6c 73 2e 66 c7 40 04 70 00 8b 43 08 c7 00 6c 75 73 68 c7 40 04 2f 46 69 6c c6 40 08 00 58 5a } //1
		$a_01_2 = {8b 43 0c c7 00 74 2e 70 68 c7 40 04 70 3f 73 6c 66 c7 40 08 3d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}