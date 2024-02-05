
rule Trojan_Win64_CobaltStrike_EN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {89 c1 c1 f9 1f 29 ca 6b ca 36 29 c8 89 c2 89 d0 83 c0 38 44 89 c1 31 c1 48 8b 95 10 03 00 00 8b 85 04 03 00 00 48 98 88 0c 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_EN_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.EN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 63 c8 41 8d 40 82 41 ff c0 30 44 0c 28 41 83 f8 0c 72 ec } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 50 72 6f 6a 65 63 74 5f 62 69 6e 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}