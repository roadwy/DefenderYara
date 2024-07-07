
rule Worm_Win32_Ramnit_A{
	meta:
		description = "Worm:Win32/Ramnit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 8f 47 08 89 57 10 68 20 00 00 e0 8f 47 24 } //1
		$a_03_1 = {76 67 2d 09 00 00 00 6a 00 6a 00 90 09 05 00 3d 09 00 00 00 90 00 } //1
		$a_01_2 = {b0 e2 88 06 46 ff 75 10 56 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}