
rule Trojan_Win32_Ranumbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 4c 24 ?? 8d 0c 32 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? ?? 89 ?? ?? c7 [0-09] 8b 45 } //1
		$a_03_1 = {c1 e9 05 89 4d ?? 8b 45 ?? 01 45 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ranumbot_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 05 89 4d ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 55 ?? 33 55 ?? 89 55 ?? 83 3d [0-08] 75 } //1
		$a_03_1 = {8b 45 e0 01 45 ec c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 [0-0c] 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}