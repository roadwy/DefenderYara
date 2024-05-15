
rule Trojan_Win64_CobaltStrike_CCHV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 44 24 70 5c 00 00 00 c7 44 24 68 74 00 00 00 c7 44 24 60 6f 00 00 00 c7 44 24 58 6c 00 00 00 c7 44 24 50 73 00 00 00 c7 44 24 48 6c 00 00 00 c7 44 24 40 69 00 00 00 c7 44 24 38 61 00 00 00 c7 44 24 30 6d 00 00 00 c7 44 24 28 5c 00 00 00 c7 44 24 20 2e } //00 00 
	condition:
		any of ($a_*)
 
}