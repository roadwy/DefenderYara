
rule Backdoor_Win32_Bewmecky_A{
	meta:
		description = "Backdoor:Win32/Bewmecky.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3c 48 0f 85 ?? ?? 00 00 80 be ?? ?? ?? ?? 54 0f 85 ?? ?? 00 00 80 be ?? ?? ?? ?? 54 0f 85 ?? ?? 00 00 80 be ?? ?? ?? ?? 50 0f 85 } //1
		$a_01_1 = {76 29 8b df 2b de 8a 06 3c 23 74 06 3c 40 74 02 fe c0 3c 40 88 04 33 74 12 } //1
		$a_01_2 = {66 3d 0d 00 74 06 66 3d 01 00 75 05 be 90 0e 00 00 66 3d 0e 00 74 06 66 3d 02 00 75 03 6a 51 5e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}