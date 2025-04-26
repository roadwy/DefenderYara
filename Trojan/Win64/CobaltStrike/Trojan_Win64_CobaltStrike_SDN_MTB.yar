
rule Trojan_Win64_CobaltStrike_SDN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ce b8 e1 83 0f 3e f7 ee ff c6 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 43 32 04 01 41 88 00 49 ff c0 3b f7 72 } //1
		$a_00_1 = {53 74 61 72 74 55 70 } //1 StartUp
		$a_00_2 = {46 69 6e 64 4e 65 78 74 56 6f 6c 75 6d 65 4d 6f 75 6e 74 50 6f 69 6e 74 57 } //1 FindNextVolumeMountPointW
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}