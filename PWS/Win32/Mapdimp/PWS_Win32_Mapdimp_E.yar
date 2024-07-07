
rule PWS_Win32_Mapdimp_E{
	meta:
		description = "PWS:Win32/Mapdimp.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c1 f8 51 50 ff 75 08 ff d6 8b 45 fc bb 8c 00 00 00 83 c0 f8 33 d2 8b cb f7 f1 85 c0 7e 33 } //4
		$a_10_1 = {76 65 72 63 6c 73 69 64 } //1 verclsid
		$a_01_2 = {c7 45 ec 6f 6b 00 00 ff 15 } //1
		$a_01_3 = {c7 45 ec 5f 4d 42 00 50 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_10_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}