
rule PWS_Win32_Beomok_A{
	meta:
		description = "PWS:Win32/Beomok.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 69 3d 25 73 26 6f 3d 25 64 } //1 %s?i=%s&o=%d
		$a_01_1 = {3c 70 61 73 73 3e 25 73 } //1 <pass>%s
		$a_03_2 = {b8 48 01 00 c0 c2 10 00 a1 90 01 04 8d 54 24 04 cd 2e 90 00 } //1
		$a_01_3 = {83 e8 05 89 46 01 c6 06 e9 a1 } //1
		$a_01_4 = {88 1c 0f 7c c2 83 a1 00 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}