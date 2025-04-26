
rule Backdoor_Win32_Likseput_D{
	meta:
		description = "Backdoor:Win32/Likseput.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 06 d0 fa 80 e2 7f 41 88 10 40 3b 4d fc 72 } //1
		$a_01_1 = {80 f1 46 d0 e9 88 4c 05 e0 40 83 f8 18 } //1
		$a_01_2 = {6b 69 6c 6c 00 00 00 00 67 65 74 66 00 00 00 00 70 75 74 66 00 00 00 00 73 74 61 72 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}