
rule Backdoor_Win32_DriWrap_SD_MTB{
	meta:
		description = "Backdoor:Win32/DriWrap.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {54 41 49 4c 3a } //1 TAIL:
		$a_81_1 = {4b 45 59 3a } //1 KEY:
		$a_03_2 = {56 57 8b fa 8b f1 8b cf e8 ?? ?? ?? ?? 85 c0 75 ?? 81 [0-06] 75 } //1
		$a_03_3 = {33 c9 2b d0 8d ?? ?? 33 ?? 0f b7 [0-04] 66 89 [0-04] 66 3b ?? 74 [0-08] 41 3b ?? 7e } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}