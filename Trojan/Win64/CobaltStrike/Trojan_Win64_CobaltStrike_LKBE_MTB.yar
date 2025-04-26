
rule Trojan_Win64_CobaltStrike_LKBE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 aa 26 00 00 31 d2 41 b9 5c 00 00 00 f7 f1 c7 44 24 50 5c 00 00 00 c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 c7 44 24 28 5c 00 00 00 c7 44 24 20 2e 00 00 00 41 b8 5c 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}