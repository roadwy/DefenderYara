
rule Ransom_Win32_Ophionlock_A{
	meta:
		description = "Ransom:Win32/Ophionlock.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 66 69 72 73 74 3d 31 00 } //1
		$a_01_1 = {65 63 69 65 73 2e 70 75 62 6c 69 63 2e 6b 65 79 00 } //1
		$a_01_2 = {77 6f 6e 27 74 20 45 56 45 52 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b 2e } //1 won't EVER get your files back.
		$a_01_3 = {79 6f 75 72 20 68 77 69 64 20 69 73 20 3a } //1 your hwid is :
		$a_01_4 = {2e 70 68 70 3f 68 77 69 64 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}