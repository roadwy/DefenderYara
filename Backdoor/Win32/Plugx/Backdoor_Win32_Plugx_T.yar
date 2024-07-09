
rule Backdoor_Win32_Plugx_T{
	meta:
		description = "Backdoor:Win32/Plugx.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b7 45 e8 0f b7 4d ea 6b c0 64 03 c1 0f b7 4d ee 6b c0 64 03 c1 3d 50 50 33 01 0f 8c ab 00 00 00 } //1
		$a_03_1 = {66 0f b6 c0 66 01 05 ?? ?? ?? ?? b8 40 42 0f 00 66 0f b6 c1 66 01 05 ?? ?? ?? ?? 88 4e 01 b8 00 e1 f5 05 } //1
		$a_01_2 = {4d 00 63 00 55 00 74 00 69 00 6c 00 2e 00 64 00 6c 00 6c 00 2e 00 70 00 69 00 6e 00 67 00 00 00 43 72 65 00 61 74 65 00 46 69 6c 00 65 57 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}