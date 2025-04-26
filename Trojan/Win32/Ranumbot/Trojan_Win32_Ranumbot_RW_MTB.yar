
rule Trojan_Win32_Ranumbot_RW_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 4d ?? 33 4d ?? 89 4d ?? 83 3d [0-06] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 45 ?? 81 05 ?? ?? ?? ?? ca f9 15 16 01 05 ?? ?? ?? ?? 8b ?? ?? 33 ?? ?? ?? ?? ?? 89 ?? ?? c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 44 24 ?? 03 ce 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 ?? ec c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 8b 45 e4 50 8d ?? ec 51 e8 ?? ?? ?? ?? 8b ?? ?? 2b ?? ?? 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}