
rule Trojan_Win64_LummacStealer_IY_MTB{
	meta:
		description = "Trojan:Win64/LummacStealer.IY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c2 44 0f b6 44 15 ?? 44 01 c0 25 ?? ?? ?? ?? 48 63 d0 8a 4c 15 ?? 88 4d ?? 48 8b 95 ?? ?? ?? ?? 4c 8b 4d ?? 42 0f b6 04 0a 44 0f b6 45 ?? 44 31 c0 88 c1 48 8b 95 ?? ?? ?? ?? 4c 8b 4d ?? 42 88 0c 0a 48 8b 45 ?? 48 83 c0 ?? 48 89 45 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}