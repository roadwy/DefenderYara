
rule Worm_Win32_Koobface_T{
	meta:
		description = "Worm:Win32/Koobface.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 73 79 73 2f 3f 61 63 74 69 6f 6e 3d 61 76 67 65 6e 26 76 3d 31 00 } //1
		$a_01_1 = {3c 6c 69 3e 46 6f 72 20 4d 69 63 72 6f 73 6f 66 74 3a 20 3c 61 20 68 72 65 66 3d } //1 <li>For Microsoft: <a href=
		$a_03_2 = {8b d8 83 fb ff 0f 84 90 01 02 00 00 8d 44 24 90 01 01 50 53 ff 15 90 01 02 40 00 8b e8 83 fd 0a 0f 86 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}