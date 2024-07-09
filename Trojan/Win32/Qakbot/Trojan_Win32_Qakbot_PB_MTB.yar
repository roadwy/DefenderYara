
rule Trojan_Win32_Qakbot_PB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 f6 2b fa 8b c6 8d 0c 16 83 e0 0f 8a 80 ?? ?? ?? ?? 32 04 0f 46 88 01 3b f3 72 ?? 5f 5e } //1
		$a_03_1 = {33 d2 8b c3 f7 75 ?? 8b 45 ?? 8a 04 02 32 04 0b 88 04 1f 43 83 ee 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_PB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af f2 8b 97 ?? ?? ?? ?? 89 b7 ?? ?? ?? ?? 31 1c 82 8b 57 ?? 31 ca 8b b7 ?? ?? ?? ?? 01 f2 42 89 97 ?? ?? ?? ?? 8b 97 ?? ?? ?? ?? 2b 57 ?? 81 c2 ?? ?? ?? ?? 09 97 ?? ?? ?? ?? 8b b7 ?? ?? ?? ?? 8d 96 ?? ?? ?? ?? 0f af d6 } //1
		$a_00_1 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //1 DrawThemeIcon
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}