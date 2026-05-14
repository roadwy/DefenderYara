
rule Trojan_Win64_SalatStealer_GXH_MTB{
	meta:
		description = "Trojan:Win64/SalatStealer.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 c0 29 d0 4c 63 d0 42 0f b6 54 14 ?? 89 d1 44 01 da 41 89 d0 41 c1 f8 ?? 41 c1 e8 ?? 44 01 c2 0f b6 d2 44 29 c2 41 89 d3 48 63 d2 44 0f b6 44 14 ?? 46 88 44 14 ?? 88 4c 14 ?? 42 02 4c 14 ?? 0f b6 c9 0f b6 54 0c ?? 30 13 48 83 c3 ?? 49 39 d9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}