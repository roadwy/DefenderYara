
rule PWS_Win32_Perfwef_gen_A{
	meta:
		description = "PWS:Win32/Perfwef.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 48 6f 6f 6b } //1 StartHook
		$a_01_1 = {53 74 6f 70 48 6f 6f 6b } //1 StopHook
		$a_00_2 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 } //1 ElementClient Window
		$a_00_3 = {45 71 75 69 70 46 75 6e 63 } //1 EquipFunc
		$a_03_4 = {8d 45 b4 50 b9 05 00 00 00 66 ba 95 19 a1 ?? ?? ?? ?? e8 } //2
		$a_01_5 = {8b 55 fc 8a 54 3a ff 32 55 f3 8b 4d fc 8a 0c 39 2a d1 88 54 38 ff 47 4e 75 de } //5
		$a_03_6 = {8a 13 80 f2 ?? 88 54 38 ff 47 43 4e 75 ea } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*2+(#a_01_5  & 1)*5+(#a_03_6  & 1)*5) >=13
 
}