
rule PWS_Win32_Sinowal_gen_U{
	meta:
		description = "PWS:Win32/Sinowal.gen!U,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b ff 83 ec 44 8b c1 c7 04 24 44 00 00 00 54 a1 ?? ?? ?? ?? ff d0 83 c4 44 eb } //2
		$a_03_1 = {6a 00 6a ff 6a 00 6a ff ff 15 ?? ?? ?? ?? 68 00 01 00 00 ff 15 ?? ?? ?? ?? 83 c4 04 50 ff 15 ?? ?? ?? ?? 83 c4 04 6a 00 ff 15 ?? ?? ?? ?? 83 c4 04 6a 00 6a ff ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15 } //2
		$a_03_2 = {c7 45 e4 20 00 00 00 (eb|e9) } //1
		$a_03_3 = {89 45 dc c7 45 d8 00 00 00 00 66 c7 05 ?? ?? ?? ?? 00 00 66 c7 45 fe 00 00 c7 45 d8 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}