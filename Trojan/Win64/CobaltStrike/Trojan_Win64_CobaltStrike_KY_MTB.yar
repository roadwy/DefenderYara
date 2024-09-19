
rule Trojan_Win64_CobaltStrike_KY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e0 ?? 4c 21 ca 0f b6 44 04 ?? 41 30 04 14 48 8d 42 ?? 48 89 c2 49 0f af d0 48 39 ca 77 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}