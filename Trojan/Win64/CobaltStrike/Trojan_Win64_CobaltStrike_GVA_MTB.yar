
rule Trojan_Win64_CobaltStrike_GVA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2b c1 48 89 44 24 78 48 8b 44 24 20 48 ff c0 48 89 44 24 20 8b 44 24 78 89 44 24 5c 8b 44 24 50 c1 e0 12 8b 4c 24 54 c1 e1 0c 0b c1 8b 4c 24 58 c1 e1 06 0b c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}