
rule Trojan_Win64_CobaltStrike_LKH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 18 48 8b 44 24 68 48 8b 4c 24 10 48 89 08 48 8b 44 24 70 8b 4c 24 18 89 08 48 8b 04 24 48 83 c0 28 48 89 04 24 e9 56 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}