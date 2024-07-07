
rule PWS_Win32_Dofoil_C{
	meta:
		description = "PWS:Win32/Dofoil.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6d 64 3d 67 72 61 62 26 64 61 74 61 3d } //1 cmd=grab&data=
		$a_00_1 = {5c 00 54 00 75 00 72 00 62 00 6f 00 46 00 54 00 50 00 5c 00 61 00 64 00 64 00 72 00 62 00 6b 00 2e 00 64 00 61 00 74 00 } //1 \TurboFTP\addrbk.dat
		$a_03_2 = {8d 45 fc e8 90 01 04 50 6a 00 6a 00 6a 28 6a 00 e8 90 01 04 e8 90 01 04 85 c0 74 90 01 01 8d 45 fc 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}