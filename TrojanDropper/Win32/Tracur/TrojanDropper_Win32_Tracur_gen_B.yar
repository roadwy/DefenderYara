
rule TrojanDropper_Win32_Tracur_gen_B{
	meta:
		description = "TrojanDropper:Win32/Tracur.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //1 Nullsoft Install System
		$a_01_1 = {fd 8d 80 00 43 4c 53 49 44 5c 7b 44 32 37 43 44 42 36 45 2d 41 45 36 44 2d 31 31 63 66 } //1
		$a_01_2 = {00 24 7b 73 79 73 47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 7d 28 31 30 32 34 2c 20 72 31 29 } //1
		$a_01_3 = {00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 fd } //1
		$a_01_4 = {6d 79 4d 75 74 65 78 22 29 20 69 20 2e 72 31 20 3f 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}