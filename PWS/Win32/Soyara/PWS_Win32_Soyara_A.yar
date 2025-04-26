
rule PWS_Win32_Soyara_A{
	meta:
		description = "PWS:Win32/Soyara.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 72 61 79 61 56 } //1 SorayaV
		$a_01_1 = {6d 6f 64 65 3d 35 26 63 6f 6d 70 69 6e 66 6f 3d } //1 mode=5&compinfo=
		$a_03_2 = {76 77 65 62 00 [0-10] 76 73 74 65 61 6c 74 68 00 } //1
		$a_01_3 = {50 4f 53 4d 61 69 6e 4d 75 74 65 78 } //1 POSMainMutex
		$a_03_4 = {54 72 61 63 6b 20 [0-10] 26 74 72 61 63 6b 3d } //1
		$a_01_5 = {0f b6 d9 03 5d fc 8a 08 d3 c3 40 8a 08 89 5d fc 84 c9 75 ec } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}