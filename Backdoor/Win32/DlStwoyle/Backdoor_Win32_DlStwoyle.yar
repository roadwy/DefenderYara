
rule Backdoor_Win32_DlStwoyle{
	meta:
		description = "Backdoor:Win32/DlStwoyle,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7b 42 35 39 35 39 43 32 35 2d 43 42 42 44 2d 34 64 63 63 2d 38 43 39 38 2d 44 41 32 35 45 42 42 33 44 38 39 46 7d } //3 {B5959C25-CBBD-4dcc-8C98-DA25EBB3D89F}
		$a_01_1 = {26 64 74 79 70 65 3d 25 73 26 64 6e 61 6d 65 3d 25 73 26 70 68 6f 6e 65 3d 25 73 } //2 &dtype=%s&dname=%s&phone=%s
		$a_01_2 = {71 25 64 5f 64 69 73 6b 2e 64 6c 6c } //2 q%d_disk.dll
		$a_01_3 = {61 63 63 25 64 } //2 acc%d
		$a_01_4 = {26 74 6d 6d 69 6e 3d 25 64 } //2 &tmmin=%d
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=5
 
}