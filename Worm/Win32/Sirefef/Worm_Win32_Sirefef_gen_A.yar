
rule Worm_Win32_Sirefef_gen_A{
	meta:
		description = "Worm:Win32/Sirefef.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 31 10 40 40 49 75 f3 b8 8c 56 90 7c } //1
		$a_03_1 = {74 08 8b 40 04 85 c0 75 f1 c3 85 f6 74 05 8b 48 10 90 09 08 00 eb 0b 81 38 } //1
		$a_03_2 = {81 38 04 00 00 80 75 24 8b 40 0c 3b 05 ?? ?? ?? ?? 75 19 8b 41 04 c7 80 b8 00 00 00 } //1
		$a_01_3 = {0f 8c f1 00 00 00 8d 85 80 fc ff ff 50 ff 75 ec c7 85 80 fc ff ff 01 00 01 00 ff 15 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2) >=2
 
}
rule Worm_Win32_Sirefef_gen_A_2{
	meta:
		description = "Worm:Win32/Sirefef.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 31 10 40 40 49 75 f3 b8 8c 56 90 7c } //1
		$a_03_1 = {74 08 8b 40 04 85 c0 75 f1 c3 85 f6 74 05 8b 48 10 90 09 08 00 eb 0b 81 38 } //1
		$a_03_2 = {81 38 04 00 00 80 75 24 8b 40 0c 3b 05 ?? ?? ?? ?? 75 19 8b 41 04 c7 80 b8 00 00 00 } //1
		$a_01_3 = {0f 8c f1 00 00 00 8d 85 80 fc ff ff 50 ff 75 ec c7 85 80 fc ff ff 01 00 01 00 ff 15 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2) >=2
 
}