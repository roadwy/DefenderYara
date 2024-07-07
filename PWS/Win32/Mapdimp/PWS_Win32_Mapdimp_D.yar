
rule PWS_Win32_Mapdimp_D{
	meta:
		description = "PWS:Win32/Mapdimp.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 02 57 6a fc 53 ff d6 8d 45 f8 57 50 8d 45 f4 6a 04 50 53 8b 1d 90 01 04 ff d3 81 7d f4 90 01 04 74 0e 90 00 } //4
		$a_10_1 = {76 65 72 63 6c 73 69 64 } //1 verclsid
		$a_01_2 = {c7 45 ec 6f 6b 00 00 ff 15 } //1
		$a_01_3 = {c7 45 ec 5f 4d 42 00 50 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_10_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}