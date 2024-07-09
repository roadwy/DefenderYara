
rule PWS_Win32_Extrew_A{
	meta:
		description = "PWS:Win32/Extrew.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 c7 44 24 ?? d4 07 66 c7 44 24 ?? 08 00 66 c7 44 24 ?? 11 00 66 c7 44 24 ?? 14 00 } //1
		$a_01_1 = {68 22 3d 01 00 ff d0 83 c4 08 3d 22 3d 01 00 7c 26 } //1
		$a_00_2 = {25 73 5c 25 64 2e 57 57 57 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}