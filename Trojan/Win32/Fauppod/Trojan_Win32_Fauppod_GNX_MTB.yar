
rule Trojan_Win32_Fauppod_GNX_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 4d 08 30 c8 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Fauppod_GNX_MTB_2{
	meta:
		description = "Trojan:Win32/Fauppod.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Fauppod_GNX_MTB_3{
	meta:
		description = "Trojan:Win32/Fauppod.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? a8 06 00 00 } //10
		$a_03_1 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? a8 06 00 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}