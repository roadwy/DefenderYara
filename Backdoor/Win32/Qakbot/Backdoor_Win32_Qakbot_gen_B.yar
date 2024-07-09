
rule Backdoor_Win32_Qakbot_gen_B{
	meta:
		description = "Backdoor:Win32/Qakbot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {7d 49 80 a5 e8 fe ff ff 00 80 a5 fc fe ff ff 00 8b 45 08 03 85 f4 fe ff ff 0f be 08 8b 85 f4 fe ff ff 99 f7 bd ec fe ff ff 0f be 82 ?? ?? ?? ?? 33 c8 88 8d fc fe ff ff 8b 45 08 } //2
		$a_03_1 = {8d 46 5c 57 50 57 ff 56 54 3b c7 89 86 ?? ?? ?? ?? 75 0f 8b 46 58 3b c7 74 08 ff d0 } //2
		$a_03_2 = {74 70 8b 45 fc 6b c0 0c 8b 4d 08 8b 44 01 08 ff 34 85 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 f8 } //2
		$a_01_3 = {25 73 5f 25 73 5f 25 75 2e 6b 63 62 } //1 %s_%s_%u.kcb
		$a_01_4 = {25 73 5c 25 73 5f 25 75 2e 63 62 } //1 %s\%s_%u.cb
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}