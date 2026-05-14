
rule Trojan_Win64_CobaltStrike_NKI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 6c 24 ?? 49 83 fd ?? 73 ?? c1 e9 ?? 42 32 4c 2c ?? 42 88 0c 2a 49 ff c5 4c 89 6c 24 ?? 41 ff c4 44 89 64 24 ?? 41 83 fc ?? 0f 8c ?? ?? ?? ?? 49 83 fd ?? 4c 8d 2d ?? ?? ?? ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}