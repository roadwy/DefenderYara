
rule Trojan_Win64_CobaltStrike_KGD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 8b c8 49 8b c1 49 f7 e0 48 c1 ea 04 48 6b c2 11 48 2b c8 8a 44 0c 40 42 30 44 05 80 49 ff c0 49 83 f8 0e 72 da } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}