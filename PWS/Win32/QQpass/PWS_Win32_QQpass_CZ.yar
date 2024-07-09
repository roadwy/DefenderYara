
rule PWS_Win32_QQpass_CZ{
	meta:
		description = "PWS:Win32/QQpass.CZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {66 bf 01 00 0f b7 c7 8b 55 fc 0f b6 44 02 ff 66 89 45 fa 8d 45 f4 66 8b 55 fa 66 83 f2 ?? e8 ?? ?? ff ff 8b 55 f4 8b c6 e8 ?? ?? ff ff 47 66 ff cb 75 d1 } //3
		$a_01_1 = {4a 6d 70 48 6f 6f 6b 4f 66 66 } //1 JmpHookOff
		$a_01_2 = {4a 6d 70 48 6f 6f 6b 4f 6e } //1 JmpHookOn
		$a_00_3 = {68 6f 6f 6b 2e 64 6c 6c } //1 hook.dll
	condition:
		((#a_02_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}