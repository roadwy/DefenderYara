
rule Trojan_Win32_SmokeLoader_HAS_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.HAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 03 6c 24 20 c7 05 ?? ?? ?? ?? 00 00 00 00 33 eb 33 e8 2b f5 8b d6 c1 e2 04 89 54 24 10 8b 44 24 24 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 37 75 } //1
		$a_03_1 = {8b d6 c1 ea 05 03 54 24 28 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 d3 31 54 24 10 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 10 29 44 24 14 81 c7 47 86 c8 61 ff 4c 24 18 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}