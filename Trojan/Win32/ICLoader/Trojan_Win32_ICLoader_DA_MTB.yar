
rule Trojan_Win32_ICLoader_DA_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 00 32 c8 a1 ?? ?? 4c 00 88 0d ?? ?? 4c 00 8b 0d ?? ?? 4c 00 8b 15 ?? ?? 4c 00 83 e1 04 03 c1 83 e2 0c a3 ?? ?? 4c 00 a1 ?? ?? 4c 00 25 ff 00 00 00 8b 0d ?? ?? 4c 00 0f af d0 55 56 8b 35 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}