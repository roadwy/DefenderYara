
rule Trojan_Win64_CobaltStrike_PLZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 01 c8 99 41 f7 fb 48 63 c2 8a 14 01 49 89 c1 42 88 14 29 40 88 3c 01 42 02 3c 29 40 0f b6 ff 8a 04 39 43 30 04 20 49 ff c4 eb ba } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}