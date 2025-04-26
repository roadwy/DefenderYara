
rule Virus_Win32_Cutef_C{
	meta:
		description = "Virus:Win32/Cutef.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 5e 3c 03 f3 66 81 3e 50 45 } //1
		$a_01_1 = {8b 46 0c 03 c1 81 38 4b 45 52 4e } //1
		$a_01_2 = {83 c6 3c 8b 36 03 75 ec 66 81 3e 50 45 0f 85 } //1
		$a_01_3 = {89 45 4e 8b f8 66 81 3f 4d 5a 0f 85 1d 01 00 00 8b 7f 3c 03 f8 66 81 3f 50 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}