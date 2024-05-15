
rule Trojan_Win64_CobaltStrike_YAU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 2b 06 85 73 31 d2 41 89 d0 42 80 3c 01 00 74 90 01 01 46 0f b7 04 01 41 89 c1 ff c2 41 c1 c9 08 45 01 c8 44 31 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}