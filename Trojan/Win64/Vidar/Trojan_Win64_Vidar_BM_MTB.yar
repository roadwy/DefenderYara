
rule Trojan_Win64_Vidar_BM_MTB{
	meta:
		description = "Trojan:Win64/Vidar.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8b 4c 24 ?? 40 88 74 1c ?? 0f b6 44 3c ?? 8b 7c 24 ?? 01 f0 8b 74 24 ?? 0f b6 c0 0f b6 44 04 ?? 48 63 4c 24 ?? 48 8b 54 24 ?? 30 04 0a 8b 4c 24 ?? 83 c1 ?? b8 ?? ?? ?? ?? 3d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}