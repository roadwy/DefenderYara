
rule Trojan_Win32_XPack_NP_MTB{
	meta:
		description = "Trojan:Win32/XPack.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 0d be 33 4c 00 03 0d ?? ?? ?? ?? c1 e1 06 2b cb 81 f9 ?? ?? ?? ?? 73 06 03 0d ?? ?? ?? ?? c1 c9 02 29 0d ?? ?? ?? ?? 2b 0d 3f 32 } //5
		$a_01_1 = {78 58 78 64 78 6a 78 } //1 xXxdxjx
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_XPack_NP_MTB_2{
	meta:
		description = "Trojan:Win32/XPack.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 c1 89 4c 24 ?? 8b 44 24 30 8b 4c 24 ?? 89 48 54 8b 44 24 ?? 8b 4c 24 30 } //3
		$a_03_1 = {83 c1 58 81 fa ?? ?? ?? ?? 89 44 24 18 89 4c 24 ?? 72 00 8b 44 24 14 8b 4c 24 ?? 89 08 8b 54 24 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}