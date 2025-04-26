
rule Trojan_Win64_CobaltStrike_AMAP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 48 89 cf 49 f7 e0 48 89 d0 48 c1 e8 03 48 8d 14 40 48 8d 04 ?? 48 01 c0 48 29 c7 0f b6 44 3c 50 41 32 04 09 48 8b 54 24 ?? 88 04 0a 48 83 c1 01 48 39 4c 24 ?? 77 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}