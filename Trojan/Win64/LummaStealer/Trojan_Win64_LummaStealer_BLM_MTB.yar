
rule Trojan_Win64_LummaStealer_BLM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 68 41 30 04 0c 8b 74 24 68 83 c6 01 b8 a2 61 8f 4b 3d c5 6a b1 f3 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}