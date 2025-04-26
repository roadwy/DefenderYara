
rule Trojan_Win64_CobaltStrike_BCP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 44 35 00 89 54 24 38 8b 54 24 38 83 e2 01 01 d0 88 04 33 48 ff c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}