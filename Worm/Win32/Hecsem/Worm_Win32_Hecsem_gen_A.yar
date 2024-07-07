
rule Worm_Win32_Hecsem_gen_A{
	meta:
		description = "Worm:Win32/Hecsem.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 } //10
		$a_02_1 = {3a 5c 68 6f 6f 6b 2e 64 6c 6c 00 90 01 01 3a 5c 73 6d 63 63 2e 65 78 65 90 00 } //1
		$a_00_2 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 73 6d 63 63 2e 65 78 65 20 2d 61 75 74 6f 72 75 6e } //1 shellexecute=smcc.exe -autorun
		$a_00_3 = {73 6d 63 63 00 00 00 00 6e 6f 74 65 70 61 64 2e 65 78 65 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}