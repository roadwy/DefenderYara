
rule Trojan_Win32_Trfijan_A{
	meta:
		description = "Trojan:Win32/Trfijan.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 00 43 00 6d 00 64 00 50 00 54 00 31 00 00 00 } //1
		$a_01_1 = {00 00 6c 00 6f 00 67 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 70 00 3d 00 00 00 } //1
		$a_01_2 = {00 00 26 00 74 00 3d 00 6e 00 65 00 77 00 26 00 75 00 3d 00 00 00 } //1
		$a_01_3 = {00 00 26 00 74 00 3d 00 75 00 70 00 64 00 61 00 74 00 65 00 26 00 75 00 3d 00 00 00 } //1
		$a_01_4 = {00 69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 73 20 2f 63 20 73 68 75 74 64 6f 77 6e 20 2d 73 00 } //1
		$a_01_5 = {00 00 44 00 65 00 73 00 63 00 6f 00 6e 00 68 00 65 00 63 00 69 00 64 00 6f 00 00 00 } //1
		$a_01_6 = {00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 36 00 39 00 2e 00 35 00 35 00 2e 00 36 00 39 00 2e 00 32 00 35 00 30 00 2f 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}