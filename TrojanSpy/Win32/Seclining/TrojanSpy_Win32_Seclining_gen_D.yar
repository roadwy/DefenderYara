
rule TrojanSpy_Win32_Seclining_gen_D{
	meta:
		description = "TrojanSpy:Win32/Seclining.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 6c 6f 67 73 65 6e 64 2e 64 6c 6c 00 4c 6f 67 53 65 6e 64 00 } //1
		$a_00_1 = {69 64 3d 25 73 26 74 79 70 65 3d 25 73 26 63 6f 6d 6d 65 6e 74 3d 25 73 26 6c 6f 67 3d 25 73 00 } //1 摩┽♳祴数┽♳潣浭湥㵴猥氦杯┽s
		$a_01_2 = {75 49 c7 45 d4 71 7f 90 3c c7 45 cc 86 0a 51 4d c7 45 d0 24 2d f8 4a c7 45 c8 36 4a b3 23 c7 45 d8 ae 4a 77 53 8b 4d cc 0f af 4d d0 0b 4d c8 0b 4d d8 89 4d d4 83 7d 0c 00 74 09 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*3) >=2
 
}