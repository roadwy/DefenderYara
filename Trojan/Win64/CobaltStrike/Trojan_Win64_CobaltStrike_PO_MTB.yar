
rule Trojan_Win64_CobaltStrike_PO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 08 49 8b 4d 90 01 01 48 63 54 24 64 48 89 94 24 90 01 04 48 8b 94 24 90 01 04 32 04 11 88 44 24 90 01 01 48 8b 84 24 90 01 04 48 8b 00 48 89 84 24 90 01 04 b8 70 76 b2 dd e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}