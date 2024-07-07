
rule PWS_Win32_Kuoog_A{
	meta:
		description = "PWS:Win32/Kuoog.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d3 8d 4d b8 51 8b 55 c0 52 6a 05 a1 90 01 03 10 50 ff d6 c6 45 d8 e8 90 00 } //2
		$a_01_1 = {8d 0c 89 8d 0c 89 8d 0c 89 8d 34 c8 56 } //2
		$a_01_2 = {75 73 3d 25 73 26 70 73 3d 25 73 26 6c 76 3d 25 64 26 71 75 3d 25 73 26 73 65 3d 25 73 } //1 us=%s&ps=%s&lv=%d&qu=%s&se=%s
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}