
rule Trojan_Win32_SmokeLoader_BKK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 eb 03 8d 49 00 8d b5 ?? ?? ff ff c7 85 ?? ?? ff ff 00 00 00 00 e8 ?? ?? ff ff 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 14 38 83 fb 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_SmokeLoader_BKK_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.BKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 } //1
		$a_03_1 = {01 44 24 1c 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b c7 c1 e8 ?? 51 03 c5 50 8d 54 24 ?? 52 89 4c 24 ?? e8 ?? ?? ?? ?? 2b 74 24 ?? 89 74 24 ?? 8b 44 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}