
rule Trojan_Win32_Mokes_RT_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ec 04 08 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 db 7e ?? e8 ?? ?? ?? ?? 30 04 37 83 fb 19 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Mokes_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Mokes.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 4d ?? 33 4d ?? 89 4d ?? 81 3d [0-08] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Mokes_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Mokes.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75 ?? 55 55 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 cf 33 ce } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}