
rule PWS_Win32_Dozmot_C{
	meta:
		description = "PWS:Win32/Dozmot.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {ff d3 3d e5 03 00 00 74 0b 3d 31 04 00 00 74 04 33 db } //2
		$a_03_1 = {80 f9 41 7c 0d 80 f9 4d 7f 08 0f be c9 83 c1 90 01 01 eb 1f 90 00 } //2
		$a_01_2 = {c1 e6 19 c1 e8 07 0b f0 0f be c1 8a 4a 01 03 c6 42 84 c9 75 e9 } //2
		$a_01_3 = {25 73 3f 75 3d 25 73 26 73 68 61 3d 25 73 26 70 3d 25 73 } //1 %s?u=%s&sha=%s&p=%s
		$a_01_4 = {25 73 2f 6c 69 6e 2e 70 68 70 3f 6d 3d 25 73 26 67 3d } //1 %s/lin.php?m=%s&g=
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}