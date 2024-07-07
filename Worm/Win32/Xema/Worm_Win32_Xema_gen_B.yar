
rule Worm_Win32_Xema_gen_B{
	meta:
		description = "Worm:Win32/Xema.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 2e 00 5c 00 52 00 45 00 43 00 59 00 43 00 4c 00 45 00 90 01 01 00 5c 00 90 00 } //10
		$a_00_1 = {46 00 69 00 6c 00 65 00 23 00 2a 00 } //1 File#*
		$a_00_2 = {26 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 } //1 &Command=
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}