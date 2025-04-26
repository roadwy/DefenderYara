
rule Trojan_Win32_SmokeLoader_WEF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.WEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 54 24 24 8b f0 c1 e6 04 03 f5 33 d6 03 c1 33 d0 2b fa 8b d7 c1 e2 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 14 8b 44 24 28 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 39 75 } //1
		$a_03_1 = {6a 00 ff 15 ?? ?? ?? ?? 8d 4c 24 78 51 6a 00 ff 15 ?? ?? ?? ?? 33 f3 31 74 24 14 8b 44 24 14 29 44 24 18 8d 44 24 1c e8 ?? ?? ?? ?? ff 4c 24 20 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}