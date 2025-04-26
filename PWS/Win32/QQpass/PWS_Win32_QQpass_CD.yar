
rule PWS_Win32_QQpass_CD{
	meta:
		description = "PWS:Win32/QQpass.CD,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 65 6e 51 51 41 63 63 6f 75 6e 74 2e 64 6c 6c } //1 TenQQAccount.dll
		$a_00_1 = {73 65 74 74 65 6c 6c 6f 76 65 72 7c 6d 72 61 64 6d 69 6e 7c } //1 settellover|mradmin|
		$a_00_2 = {68 75 61 69 5f 68 75 61 69 } //1 huai_huai
		$a_00_3 = {6d 72 73 74 72 3d } //1 mrstr=
		$a_00_4 = {41 44 44 5f 53 45 4e 44 7c } //1 ADD_SEND|
		$a_02_5 = {8b 03 05 00 00 2f 00 50 6a 00 68 79 01 00 00 68 ?? ?? ?? ?? 6a 00 8b 0b 81 c1 00 00 21 00 ba ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 06 83 3e 00 74 ?? 33 c0 a3 ?? ?? ?? ?? 8b 06 83 c0 05 a3 ?? ?? ?? ?? 68 00 00 4f 00 6a 07 6a 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*10) >=13
 
}