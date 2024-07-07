
rule Trojan_Win64_CobaltStrike_IND_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 83 e2 07 0f b6 54 15 00 32 14 07 88 14 03 48 83 c0 01 48 39 c6 75 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}