
rule Trojan_Win64_CobaltStrike_FL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 31 d2 49 f7 f2 41 0f b6 04 13 41 30 04 09 48 ff c1 49 39 c8 74 ?? 48 89 c8 4c 09 d0 48 c1 e8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}