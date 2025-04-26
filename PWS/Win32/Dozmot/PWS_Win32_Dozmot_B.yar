
rule PWS_Win32_Dozmot_B{
	meta:
		description = "PWS:Win32/Dozmot.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {2b de 8a 04 33 55 04 ?? 34 ?? 2c ?? 47 88 06 46 ff 15 28 60 00 10 3b f8 7c e8 } //4
		$a_01_1 = {2f 31 47 65 74 4d 62 2e 61 73 70 00 } //1
		$a_01_2 = {26 6d 62 68 3d 00 } //1 洦桢=
		$a_01_3 = {61 63 74 69 6f 6e 3d 64 6f 6d 6f 64 26 } //1 action=domod&
		$a_01_4 = {3d 73 68 6f 77 6d 62 6d 26 } //1 =showmbm&
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}