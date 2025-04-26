
rule Worm_Win32_Bononabeer_A{
	meta:
		description = "Worm:Win32/Bononabeer.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 72 65 20 69 37 20 4e 61 62 69 72 65 20 43 6f 6d 6d 75 6e 69 74 69 65 7a 20 3a 3a 2e 00 } //1
		$a_01_1 = {73 65 74 74 69 6e 67 73 2e 65 78 65 00 } //1
		$a_01_2 = {46 69 6c 65 73 3a 20 66 69 6c 6d 20 62 6f 6b 65 70 2e 33 67 70 2c 70 65 72 61 77 61 6e 2e 6a 70 67 00 } //1
		$a_01_3 = {74 79 6f 2e 6d 61 6b 61 6e 61 6e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}