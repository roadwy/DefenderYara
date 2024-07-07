
rule Trojan_Win64_CobaltStrike_ZJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 8a 14 1e 48 89 f8 48 c1 f8 90 01 01 42 8a 0c 18 42 88 0c 1e 42 88 14 18 48 ff c6 4c 01 c7 49 39 f2 75 90 02 40 8a 0c 10 30 0c 3e ff c0 48 ff c6 49 39 f1 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}