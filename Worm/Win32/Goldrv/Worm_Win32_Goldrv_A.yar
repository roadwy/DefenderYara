
rule Worm_Win32_Goldrv_A{
	meta:
		description = "Worm:Win32/Goldrv.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {5c 00 6e 00 65 00 77 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 } //2 \new folder
		$a_01_2 = {54 65 6d 70 20 75 70 64 61 74 65 20 66 69 6c 65 3a } //1 Temp update file:
		$a_01_3 = {5c 76 65 72 74 69 67 6f 64 6c } //3 \vertigodl
		$a_01_4 = {2e 76 76 73 2e 69 72 2f 00 } //2
		$a_03_5 = {64 6c 76 65 72 73 69 6f 6e 2e 70 68 70 3f 69 64 3d [0-20] 64 6c 75 70 64 61 74 65 2e 64 61 74 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_03_5  & 1)*2) >=9
 
}