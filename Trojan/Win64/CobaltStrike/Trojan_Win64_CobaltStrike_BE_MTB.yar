
rule Trojan_Win64_CobaltStrike_BE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 c1 83 e1 90 01 01 8a 0c 0a 41 90 01 03 48 90 01 02 48 90 01 03 75 90 01 01 31 c0 41 90 01 02 7e 90 01 01 48 90 01 02 83 e1 90 01 01 8a 0c 0a 41 90 01 03 48 90 01 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BE_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 eb 03 d3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1f 2b c8 8d 04 0b 48 98 42 0f b6 14 18 41 8d 04 18 41 32 56 ff ff c3 48 63 c8 88 14 39 8b 94 24 98 00 00 00 41 03 d2 3b da 72 } //01 00 
		$a_01_1 = {5f 24 47 58 6f 3e 45 3f 41 43 61 48 6a 46 3e 6f 67 59 47 53 69 61 55 38 6c 4a 6c 74 55 69 } //00 00 
	condition:
		any of ($a_*)
 
}