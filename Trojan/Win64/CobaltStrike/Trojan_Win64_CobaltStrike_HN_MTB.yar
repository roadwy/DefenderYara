
rule Trojan_Win64_CobaltStrike_HN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 90 01 01 8a 54 15 90 01 01 32 14 07 88 14 03 48 ff c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}