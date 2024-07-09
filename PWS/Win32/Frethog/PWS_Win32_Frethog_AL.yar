
rule PWS_Win32_Frethog_AL{
	meta:
		description = "PWS:Win32/Frethog.AL,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_03_1 = {8b 44 24 04 03 c1 80 30 ?? 41 3b 4c 24 08 7c f0 } //5
		$a_01_2 = {3d 25 73 26 73 72 76 3d 25 73 26 69 64 31 3d 25 73 26 64 6a 31 3d 25 73 26 70 63 3d 25 73 } //3 =%s&srv=%s&id1=%s&dj1=%s&pc=%s
		$a_01_3 = {8b 4d 14 33 d2 8b 04 96 41 83 e1 1f d3 c0 33 c7 89 04 96 42 3b d3 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*5) >=8
 
}