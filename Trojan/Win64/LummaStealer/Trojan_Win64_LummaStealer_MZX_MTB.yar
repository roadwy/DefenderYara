
rule Trojan_Win64_LummaStealer_MZX_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.MZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 8a 84 04 ?? ?? ?? ?? 48 63 4c 24 ?? 48 8b 54 24 40 30 04 0a 8b 7c 24 ?? 83 c7 01 b8 40 83 d0 1a 45 89 fe 8b 74 24 ?? 8b 5c 24 30 3d c8 41 b1 35 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}