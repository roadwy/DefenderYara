
rule Trojan_Win64_Cobaltstrike_FG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 28 00 00 00 00 8b 44 24 24 48 63 4c 24 28 0f b6 4c 0c 50 48 8b 94 24 ?? ?? ?? ?? 0f b6 04 02 33 c1 8b 4c 24 24 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 8b 44 24 28 ff c0 89 44 24 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_FG_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 0c ?? 42 32 44 0f ?? 41 88 41 ?? 41 8d 42 ?? 41 83 c2 04 48 63 c8 49 8b c0 48 f7 e1 48 c1 ea 02 48 6b c2 16 48 2b c8 0f b6 44 0c ?? 42 32 44 0e ?? 41 88 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}