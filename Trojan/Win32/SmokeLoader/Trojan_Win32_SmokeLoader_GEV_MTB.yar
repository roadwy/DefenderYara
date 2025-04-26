
rule Trojan_Win32_SmokeLoader_GEV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 45 ?? 8d 0c 37 31 4d ?? 50 89 45 ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_SmokeLoader_GEV_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b7 b8 c4 23 c7 45 ?? ec 1c c1 2a c7 45 ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 46 2e d2 6c c7 45 ?? 3d e7 ce 7f c7 45 ?? 97 34 4d 72 c7 45 ?? 28 8c 70 73 c7 45 ?? a7 75 bc 74 c7 45 ?? 5e 40 4f 66 c7 85 ?? ?? ?? ?? db 81 79 6e c7 45 ?? e4 bf 0e 0d c7 85 ?? ?? ?? ?? 1b 3d 01 4c c7 85 ?? ?? ?? ?? 37 ac b2 42 c7 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}