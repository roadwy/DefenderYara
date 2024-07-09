
rule PWS_Win32_Wowsteal_AO_dll{
	meta:
		description = "PWS:Win32/Wowsteal.AO!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 78 01 61 75 ?? 80 78 02 75 75 ?? 80 78 03 6e } //1
		$a_01_1 = {8d 54 24 04 2b c8 6a 06 52 83 e9 05 50 6a ff c6 44 24 14 e9 89 4c 24 15 } //2
		$a_03_2 = {b9 09 00 00 00 bf ?? ?? 00 10 8d 34 10 33 db f3 a6 74 0f 42 81 fa 00 00 08 00 72 } //2
		$a_01_3 = {33 db b0 90 68 00 a0 57 00 c6 44 24 10 e9 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2) >=2
 
}