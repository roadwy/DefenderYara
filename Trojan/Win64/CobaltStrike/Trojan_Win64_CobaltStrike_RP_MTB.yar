
rule Trojan_Win64_CobaltStrike_RP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d1 44 8d 04 09 80 c9 ?? 00 c2 44 00 c2 28 ca 80 c2 01 88 15 ?? ?? ?? 00 8a 05 ?? ?? ?? 00 89 c1 89 c2 80 e2 ?? 00 c2 34 ?? f6 d1 44 8d 04 09 80 c9 ?? 00 c2 44 00 c2 28 ca 80 c2 01 88 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}