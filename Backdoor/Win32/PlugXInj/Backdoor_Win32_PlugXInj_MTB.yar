
rule Backdoor_Win32_PlugXInj_MTB{
	meta:
		description = "Backdoor:Win32/PlugXInj!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {80 34 30 20 40 3b c7 7c } //1
		$a_03_1 = {f7 e1 8b c1 2b c2 d1 ?? 03 c2 c1 e8 ?? 69 c0 ?? 00 00 00 8b d1 2b d0 8a 84 15 ?? ?? ?? ?? 30 04 31 41 3b cf 7c d5 68 ?? ?? 00 00 ff 15 ?? ?? ?? ?? e8 } //1
		$a_03_2 = {f7 e1 c1 ea ?? 8b c2 c1 e0 ?? 2b c2 03 c0 8b d1 2b d0 8a 44 15 ?? 30 04 31 41 3b cf 7c dd 68 ?? ?? 00 00 ff 15 ?? ?? ?? ?? e8 } //1
		$a_03_3 = {f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 ?? 6b c0 ?? 8b d1 2b d0 8a 44 15 ?? 30 04 31 41 3b cf 7c db } //1
		$a_03_4 = {f7 e1 c1 ea ?? 6b d2 ?? 8b c1 2b c2 8a 54 05 ?? 30 14 31 41 3b cf 7c e3 } //1
		$a_03_5 = {f7 e1 c1 ea ?? 69 d2 ?? ?? 00 00 8b c1 2b c2 8a 94 05 ?? ?? ?? ?? 30 14 31 41 3b cf 7c dd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=2
 
}