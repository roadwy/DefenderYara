
rule Backdoor_Win64_PlugXInj_MTB{
	meta:
		description = "Backdoor:Win64/PlugXInj!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 30 20 48 ff c0 48 ff c9 75 } //1
		$a_03_1 = {49 8b c0 49 ff c3 48 f7 e6 48 8b c6 48 ff c6 48 c1 ea ?? 48 6b d2 ?? 48 2b c2 0f b6 44 05 ?? 41 30 43 ff 48 ff c9 75 } //1
		$a_03_2 = {49 8b c1 48 ff c7 48 f7 e1 48 8b c1 48 ff c1 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b c2 0f b6 44 04 ?? 30 47 ff 49 ff c8 75 d6 } //1
		$a_03_3 = {49 8b c1 49 ff c3 48 f7 e1 48 8b c1 48 ff c1 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b c2 0f b6 84 05 ?? ?? ?? ?? 41 30 43 ff 49 ff c8 75 d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}