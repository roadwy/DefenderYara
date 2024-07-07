
rule PWS_Win32_Mapdimp_F{
	meta:
		description = "PWS:Win32/Mapdimp.F,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c0 f8 50 56 ff 75 08 ff d3 8b 45 fc bb 8c 00 00 00 83 c0 f8 33 d2 8b cb 89 7d f0 f7 f1 85 c0 7e 36 } //4
		$a_10_1 = {41 44 56 41 50 49 33 32 2e 64 6c 6c } //1 ADVAPI32.dll
		$a_01_2 = {c7 45 ec 6f 6b 00 00 ff 15 } //1
		$a_01_3 = {c7 45 ec 5f 4d 42 00 50 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_10_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}