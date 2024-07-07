
rule PWS_Win32_Frethog_L_dll{
	meta:
		description = "PWS:Win32/Frethog.L!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {8b c0 83 3d 90 01 02 40 00 00 75 19 6a 00 a1 90 01 02 40 00 50 68 90 01 02 40 00 6a 03 e8 90 01 04 a3 90 01 02 40 00 c3 90 00 } //1
		$a_02_1 = {40 00 00 74 12 a1 90 01 02 40 00 50 e8 90 01 04 33 c0 a3 90 01 02 40 00 c3 90 00 } //1
		$a_01_2 = {53 74 61 72 74 48 6f 6f 6b 32 } //1 StartHook2
		$a_01_3 = {53 74 6f 70 48 6f 6f 6b 32 } //1 StopHook2
		$a_00_4 = {48 6f 6f 6b 2e 64 6c 6c } //1 Hook.dll
		$a_01_5 = {51 33 36 30 53 61 66 65 4d 6f 6e 43 6c 61 73 73 } //1 Q360SafeMonClass
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}