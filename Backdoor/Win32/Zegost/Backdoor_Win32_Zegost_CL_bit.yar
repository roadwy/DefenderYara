
rule Backdoor_Win32_Zegost_CL_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CL!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 } //2
		$a_03_1 = {66 81 38 4d 5a 0f 85 f9 00 00 00 8b 70 3c 03 f0 81 3e 50 45 00 00 0f 85 e8 00 00 00 bf 00 20 00 00 8b 1d ?? ?? ?? 00 6a 04 57 ff 76 ?? ff 76 ?? ff d3 } //1
		$a_03_2 = {03 4d 08 89 45 f4 51 50 e8 ?? ?? ?? 00 8b 45 f4 83 c4 0c 89 46 f8 8b 45 10 ff 45 fc 83 c6 28 8b 00 0f b7 40 06 39 45 fc 7c } //1
		$a_01_3 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 41 70 70 50 61 74 63 68 5c } //1 %ProgramFiles%\AppPatch\
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}