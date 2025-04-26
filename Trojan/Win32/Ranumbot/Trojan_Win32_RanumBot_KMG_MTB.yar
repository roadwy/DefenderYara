
rule Trojan_Win32_RanumBot_KMG_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 44 24 10 a1 ?? ?? ?? ?? 3d 1a 0c 00 00 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_RanumBot_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 44 24 10 a1 ?? ?? ?? ?? 3d 4a 04 00 00 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_RanumBot_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ?? 8b 45 ?? ?? 45 ?? 8b 45 ?? ?? f8 8b 45 ?? ?? c3 33 f8 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RanumBot_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 7c 24 ?? 89 54 24 ?? 8b 44 24 ?? ?? 44 24 ?? 8b 44 24 ?? ?? 44 24 ?? 8b 7c 24 ?? a1 ?? ?? ?? ?? 03 fb 3d 72 05 00 00 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}