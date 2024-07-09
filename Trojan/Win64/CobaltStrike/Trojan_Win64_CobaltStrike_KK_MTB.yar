
rule Trojan_Win64_CobaltStrike_KK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff } //1
		$a_01_1 = {4c 6f 61 64 65 72 2e 6e 69 6d } //1 Loader.nim
		$a_01_2 = {62 63 6d 6f 64 65 2e 6e 69 6d } //1 bcmode.nim
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win64_CobaltStrike_KK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 93 24 49 92 41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 6b d2 38 2b c2 48 63 c8 48 8d 05 b4 20 02 00 8a 04 01 42 32 04 0e 41 88 01 49 ff c1 44 3b c5 72 c4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_KK_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 ?? 8b 44 24 ?? 39 44 24 04 73 ?? 8b 44 24 ?? 99 81 e2 ?? ?? ?? ?? 03 c2 25 ?? ?? ?? ?? 2b c2 88 04 24 8b 44 24 ?? 0f b6 0c 24 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}