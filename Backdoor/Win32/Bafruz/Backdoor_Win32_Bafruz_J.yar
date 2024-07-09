
rule Backdoor_Win32_Bafruz_J{
	meta:
		description = "Backdoor:Win32/Bafruz.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 7b 0d 00 74 c2 33 c0 90 09 19 00 75 0d 53 68 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 } //2
		$a_01_1 = {77 5f 64 69 73 74 72 69 62 2e 65 78 65 00 } //1
		$a_01_2 = {4e 4f 44 5f 54 58 54 00 ff ff ff ff 04 00 00 00 65 73 65 74 00 } //1
		$a_03_3 = {b9 40 42 0f 00 ba 3b d9 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 75 ?? c6 05 ?? ?? ?? ?? 00 eb } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}