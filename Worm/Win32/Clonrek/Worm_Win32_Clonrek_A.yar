
rule Worm_Win32_Clonrek_A{
	meta:
		description = "Worm:Win32/Clonrek.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 50 5c 76 78 6a 74 67 2e 65 78 65 20 61 75 74 6f 72 75 6e 6e 65 64 } //01 00  MP\vxjtg.exe autorunned
		$a_01_1 = {72 67 68 6f 73 74 2e 72 75 2f 64 6f 77 6e 6c 6f 61 64 2f 34 32 38 37 36 35 38 33 } //01 00  rghost.ru/download/42876583
		$a_01_2 = {70 6f 63 6c 62 6d 31 32 30 38 32 33 47 65 46 6f 72 63 65 20 39 36 30 30 20 47 54 76 31 77 32 35 36 6c 34 2e 62 69 6e } //01 00  poclbm120823GeForce 9600 GTv1w256l4.bin
		$a_01_3 = {43 4c 43 4b 00 00 00 00 4d 69 6e 69 6e 67 20 73 74 61 72 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}