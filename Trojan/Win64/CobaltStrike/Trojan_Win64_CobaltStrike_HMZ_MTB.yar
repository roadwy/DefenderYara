
rule Trojan_Win64_CobaltStrike_HMZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 44 05 b0 83 f0 0a 8b 95 4c 03 00 00 48 63 d2 88 44 15 b0 83 85 4c 03 00 00 01 8b 85 4c 03 00 00 3b 85 ?? 03 00 00 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}