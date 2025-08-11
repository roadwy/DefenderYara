
rule Trojan_Win64_LummaStealer_ZSS_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.ZSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 f6 4d 89 fe 4d 89 ef 48 8d 7d f8 41 bd 0b 29 05 4d 01 c1 0f b6 c1 48 8b 4d ?? 0f b6 04 01 48 63 4d f0 41 30 04 0f 44 8b 65 ?? 41 83 c4 01 b8 c5 bc 26 c3 3d d1 c3 86 f7 0f 8e ?? ?? ?? ?? e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}