
rule PWS_Win32_Cuepilini_A{
	meta:
		description = "PWS:Win32/Cuepilini.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 8d 7d a0 f3 a5 8d 85 8c fa ff ff 66 a5 50 8d 85 98 fd ff ff 50 a4 ff } //01 00 
		$a_01_1 = {6e 7a 7a 76 3c 2f 2f 77 77 77 30 } //01 00  nzzv<//www0
		$a_01_2 = {64 33 64 38 64 32 2e 69 6e 69 00 } //01 00 
		$a_01_3 = {61 73 44 66 33 48 6a 38 6c 70 6f 76 78 58 6d 00 } //01 00  獡晄䠳㡪灬癯塸m
		$a_01_4 = {26 73 74 72 50 61 73 73 77 6f 72 64 3d 00 } //01 00  猦牴慐獳潷摲=
		$a_01_5 = {73 74 72 4c 65 66 74 50 77 3d 00 } //01 00 
		$a_01_6 = {56 33 4c 52 75 6e 2e 65 78 65 00 } //01 00 
		$a_01_7 = {4e 73 61 76 73 76 63 2e 65 78 65 00 } //01 00 
		$a_01_8 = {25 2a 5b 5e 3d 5d 3d 25 5b 5e 26 5d } //01 00  %*[^=]=%[^&]
		$a_01_9 = {64 66 6c 6f 67 69 6e 3d 00 } //01 00 
		$a_01_10 = {6c 5f 70 77 64 3d } //00 00  l_pwd=
	condition:
		any of ($a_*)
 
}