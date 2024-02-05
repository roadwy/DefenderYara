
rule Trojan_Win64_CobaltStrike_BO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 84 c0 74 2a 8b 45 fc 8d 50 01 89 55 fc 89 c2 48 8b 45 10 48 01 d0 0f b7 00 66 89 45 f6 0f b7 55 f6 8b 45 f8 c1 c8 08 01 d0 31 45 f8 eb } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BO_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 1f e8 90 01 04 33 d2 48 98 48 2b f5 48 f7 f6 49 8b 07 fe c2 41 32 14 06 42 88 14 33 48 8b 0f 46 30 24 31 49 ff c6 49 8b 77 90 01 01 49 8b 2f 48 8b ce 48 2b cd 4c 3b f1 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}