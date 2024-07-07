
rule Worm_Win32_Kerm_A{
	meta:
		description = "Worm:Win32/Kerm.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {54 5f 66 69 72 65 5f 74 61 73 6b 90 01 07 54 5f 73 72 75 72 74 75 70 90 00 } //10
		$a_01_1 = {0c 6f 6e 65 5f 72 75 6e 54 69 6d 65 72 } //2
		$a_00_2 = {6b 65 79 6c 6f 67 } //1 keylog
		$a_00_3 = {6b 65 79 70 72 65 73 73 } //1 keypress
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=13
 
}