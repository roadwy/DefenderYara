
rule Trojan_Win64_NightHawk_JK_MTB{
	meta:
		description = "Trojan:Win64/NightHawk.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 ?? 8b 44 24 ?? 48 3d ?? ?? ?? ?? 73 ?? 8b 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 83 f0 ?? 8b 4c 24 ?? 88 84 0c ?? ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}