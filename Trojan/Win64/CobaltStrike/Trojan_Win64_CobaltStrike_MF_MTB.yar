
rule Trojan_Win64_CobaltStrike_MF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {35 fd 00 00 00 88 05 ab 54 00 00 0f b6 05 a4 54 00 00 83 e0 6e 88 05 9b 54 00 00 0f b6 05 94 54 00 00 83 c8 43 88 05 8b 54 00 00 0f b6 05 84 54 00 00 2d 82 a3 09 53 89 05 75 54 00 00 0f b6 05 72 54 00 00 0d ca da ac 51 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_MF_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {48 8b 83 e8 00 00 00 45 8b 04 01 49 83 c1 04 8b 83 8c 00 00 00 33 83 d0 00 00 00 44 0f af 05 90 01 04 83 e8 04 31 05 90 01 04 8b 43 60 09 05 90 01 04 8b 83 f0 00 00 00 2b 05 90 01 04 41 8b d0 01 83 c0 00 00 00 48 8b 05 90 01 04 c1 ea 08 48 63 88 94 00 00 00 48 8b 80 08 01 00 00 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}