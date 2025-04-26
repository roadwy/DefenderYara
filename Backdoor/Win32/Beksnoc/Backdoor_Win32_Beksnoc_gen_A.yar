
rule Backdoor_Win32_Beksnoc_gen_A{
	meta:
		description = "Backdoor:Win32/Beksnoc.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 81 fa e3 00 00 00 74 17 8b 45 ?? 03 45 ?? 0f be 08 81 f1 e3 00 00 00 } //1
		$a_01_1 = {0f be 42 05 83 f8 2b 0f 85 } //1
		$a_03_2 = {c7 45 ec 3d 0d 00 00 8b 0d ?? ?? ?? ?? 83 e9 40 f7 d9 1b c9 } //1
		$a_01_3 = {45 53 43 4b 3a 25 75 00 } //1 卅䭃┺u
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}