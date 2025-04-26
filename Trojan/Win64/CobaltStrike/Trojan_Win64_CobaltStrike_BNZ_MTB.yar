
rule Trojan_Win64_CobaltStrike_BNZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 20 8b 44 24 58 39 44 24 20 7d 5d 48 63 44 24 ?? 48 8b 4c 24 50 0f b6 04 01 33 44 24 60 48 63 4c 24 ?? 48 8b 54 24 28 88 04 0a 48 63 44 24 20 48 8b 4c 24 28 } //5
		$a_03_1 = {99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 28 88 04 0a eb } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}