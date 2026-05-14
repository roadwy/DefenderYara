
rule Trojan_Win64_CobaltStrike_CX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 83 e2 ?? 8a 14 0a 41 30 14 00 48 ff c0 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}