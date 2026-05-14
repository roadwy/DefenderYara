
rule Trojan_Win64_CobaltStrike_BZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 c7 40 20 40 00 00 00 48 c7 40 28 00 00 00 08 48 c7 40 30 00 00 00 00 48 89 c3 b9 07 00 00 00 48 89 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_BZ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 0f b6 08 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 10 8b 45 ?? 4c 63 c0 48 8b 45 ?? 4c 01 c0 31 ca 88 10 83 45 ?? ?? 83 45 ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}