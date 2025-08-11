
rule Trojan_Win64_CobaltStrike_FIZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c3 ff c3 83 e0 07 42 8a 04 20 30 07 48 ff c7 3b de 7c e6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}