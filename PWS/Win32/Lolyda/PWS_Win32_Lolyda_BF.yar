
rule PWS_Win32_Lolyda_BF{
	meta:
		description = "PWS:Win32/Lolyda.BF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 75 63 6f 6d 72 65 73 2e 64 6c 6c 00 00 00 00 79 75 6d 69 64 69 6d 61 70 2e 64 6c 6c 00 00 00 79 75 6b 73 75 73 65 72 2e 64 6c 6c 00 } //1
		$a_01_1 = {53 50 8d 45 cc 6a 15 50 ff 75 e8 ff d7 6a 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule PWS_Win32_Lolyda_BF_2{
	meta:
		description = "PWS:Win32/Lolyda.BF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 43 01 9c c6 43 02 e8 c6 43 07 9d c6 43 08 61 } //2
		$a_03_1 = {73 20 80 b9 90 01 04 5f 74 10 41 56 89 0d 90 01 04 e8 90 01 04 59 eb dd c6 81 90 01 04 40 90 00 } //1
		$a_03_2 = {6a 0e 83 c3 36 51 50 66 c7 45 90 01 01 42 4d 89 5d 90 01 01 66 89 7d 90 01 01 66 89 7d 90 01 01 c7 45 90 01 01 36 00 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}