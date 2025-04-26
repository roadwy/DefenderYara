
rule Worm_Win32_Playnro_A{
	meta:
		description = "Worm:Win32/Playnro.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {63 6d 64 00 [0-10] 6f 70 65 6e 00 [0-20] 77 69 6e 6c 67 6e [0-05] 65 78 65 } //5
		$a_03_1 = {63 6f 70 79 [0-20] 2f 63 20 61 74 74 72 69 62 20 2d 68 20 2d 73 } //1
		$a_01_2 = {73 74 61 72 74 20 6e 65 77 20 67 61 6d 65 } //1 start new game
		$a_01_3 = {00 5c 4d 79 52 00 } //1 尀祍R
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}