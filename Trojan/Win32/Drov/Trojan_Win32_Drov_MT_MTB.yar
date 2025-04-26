
rule Trojan_Win32_Drov_MT_MTB{
	meta:
		description = "Trojan:Win32/Drov.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 07 00 00 "
		
	strings :
		$a_00_0 = {b0 6e 6a 00 88 84 24 c8 01 00 00 8d 44 24 18 50 6a 09 8d 8c 24 c8 01 00 00 51 56 c7 84 24 d0 01 00 00 46 75 6e 46 c7 84 24 d4 01 00 00 75 6e 46 75 } //10
		$a_80_1 = {47 65 74 54 65 6d 70 50 61 74 68 57 } //GetTempPathW  3
		$a_80_2 = {50 61 74 68 41 70 70 65 6e 64 57 } //PathAppendW  3
		$a_80_3 = {53 48 41 4d 70 6c 65 2e 64 61 74 } //SHAMple.dat  3
		$a_80_4 = {53 6f 66 74 77 61 72 65 5c 53 48 41 4d 70 6c 65 } //Software\SHAMple  3
		$a_80_5 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //gethostbyname  3
		$a_80_6 = {77 77 77 2e 73 68 61 6d 70 6c 65 2e 72 75 } //www.shample.ru  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=20
 
}