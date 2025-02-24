
rule Trojan_Win64_CobaltStrike_OTV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d cb 3d 00 00 88 44 24 31 48 8b 05 16 2c 18 00 48 69 c0 63 4f 00 00 0f b7 0d ?? ?? ?? ?? 48 03 c8 48 8b c1 66 89 05 ?? ?? ?? ?? 48 63 44 24 54 48 b9 07 61 c5 2f d5 28 03 00 48 2b c1 89 05 eb 2b 18 00 48 8b 44 24 78 48 8b 0d e7 2b 18 00 48 2b c8 48 8b c1 48 8b 0d ?? ?? ?? ?? 48 33 c8 48 8b c1 48 89 05 cd 2b 18 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}