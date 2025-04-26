
rule Trojan_Win64_Cobaltstrike_AF_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c8 99 44 8b 4d ?? 41 f7 f9 4c 63 d2 42 0f b6 14 11 41 31 d0 45 88 c3 48 8b 8d ?? ?? ?? ?? 4c 63 55 ?? 46 88 1c 11 8b 45 ?? 83 c0 ?? 89 45 28 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}