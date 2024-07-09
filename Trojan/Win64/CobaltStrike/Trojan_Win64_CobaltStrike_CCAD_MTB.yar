
rule Trojan_Win64_CobaltStrike_CCAD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 b9 39 e2 94 f4 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}