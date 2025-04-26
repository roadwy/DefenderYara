
rule Backdoor_Win32_Caphaw_R{
	meta:
		description = "Backdoor:Win32/Caphaw.R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 63 6d 64 3d 70 69 6e 67 26 6e 65 74 3d } //1 &cmd=ping&net=
		$a_01_1 = {26 63 6d 64 3d 6c 6f 67 26 77 3d 65 72 72 26 6e 65 74 3d } //1 &cmd=log&w=err&net=
		$a_03_2 = {72 6f 6f 74 6b 69 74 [0-05] 23 54 45 58 54 23 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}