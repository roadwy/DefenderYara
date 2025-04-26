
rule Trojan_Win64_CobaltStrike_ID_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 48 8b 45 ?? 41 89 c0 8b 45 ?? 48 98 48 8b 55 ?? 48 01 d0 44 31 c1 89 ca 88 10 83 45 ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}