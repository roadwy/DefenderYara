
rule PWS_Win32_Bistik_A{
	meta:
		description = "PWS:Win32/Bistik.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {be 88 00 00 00 57 56 6a 01 53 e8 90 01 04 57 e8 90 01 04 83 c4 14 33 c0 8a c8 80 c1 90 01 01 30 0c 18 40 3b c6 72 f3 6a 01 58 90 00 } //2
		$a_02_1 = {89 5d fc 8d 45 90 01 01 66 0f be 91 90 01 04 c1 e2 02 66 89 10 41 40 40 83 f9 90 01 01 7c ea 8d 45 90 01 01 c7 45 e0 4a 00 00 00 89 45 90 00 } //1
		$a_01_2 = {49 45 3a 50 61 73 73 77 6f 72 64 2d 50 72 6f 74 65 63 74 65 64 20 73 69 74 65 73 } //1 IE:Password-Protected sites
		$a_00_3 = {61 70 70 6d 67 6d 74 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}