
rule Trojan_Win64_CobaltStrike_LKE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 ed c1 fa 05 8b c2 c1 e8 90 01 01 03 d0 8b c5 ff c5 6b 90 01 02 2b c2 48 63 c8 48 8b 44 24 38 42 90 01 07 41 32 90 01 02 41 88 90 01 02 49 90 01 02 3b 90 01 02 30 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}