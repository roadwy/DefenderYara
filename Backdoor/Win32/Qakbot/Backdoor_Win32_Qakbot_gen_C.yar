
rule Backdoor_Win32_Qakbot_gen_C{
	meta:
		description = "Backdoor:Win32/Qakbot.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b c8 81 e1 ff 00 00 00 8a 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 e4 } //2
		$a_03_1 = {8d 46 5c 57 50 57 ff 56 54 3b c7 89 86 ?? ?? ?? ?? 75 0f 8b 46 58 3b c7 74 08 ff d0 } //2
		$a_03_2 = {74 63 8b f0 8b 40 08 ff 34 85 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 24 } //2
		$a_01_3 = {8a 54 05 fc 30 54 0d f4 40 83 f8 04 } //2
		$a_01_4 = {26 62 67 3d 25 73 26 69 74 3d 25 75 26 73 61 6c 74 3d 25 73 } //1 &bg=%s&it=%u&salt=%s
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=3
 
}