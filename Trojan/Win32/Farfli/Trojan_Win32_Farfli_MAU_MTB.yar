
rule Trojan_Win32_Farfli_MAU_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 8b 74 24 0c c1 ee 03 f6 44 24 0c 07 74 01 46 85 f6 74 1e 57 8b 7c 24 0c 68 00 40 00 10 57 6a 20 e8 12 00 00 00 83 c4 0c 83 c7 08 83 ee 01 75 e8 5f 8b 44 24 08 5e c3 8b 54 24 08 53 8b 5c 24 08 55 56 8b 32 69 eb b9 79 37 9e 57 8b 7a 04 85 } //10
		$a_01_1 = {6d 6f 64 5f 73 30 62 65 69 74 2e 64 6c 6c } //1 mod_s0beit.dll
		$a_01_2 = {5f 54 77 4d 6f 75 73 65 57 68 65 65 6c 40 34 } //1 _TwMouseWheel@4
		$a_01_3 = {5f 54 77 44 65 6c 65 74 65 42 61 72 40 34 } //1 _TwDeleteBar@4
		$a_01_4 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}