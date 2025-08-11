
rule Trojan_Win64_CobaltStrike_PGCS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PGCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 f7 f1 8b 44 24 ?? 89 d1 0f b6 4c 0c ?? 31 c8 88 c2 48 8b 44 24 ?? 8b 4c 24 ?? 88 14 08 8b 44 24 ?? 83 c0 01 89 44 24 ?? eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}