
rule Trojan_Win64_CobaltStrike_GFT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 8b 00 48 03 44 24 28 48 89 84 24 88 00 00 00 48 8b 84 24 88 00 00 00 0f b6 00 0f b6 4c 24 20 33 c1 89 44 24 30 0f b6 44 24 30 88 44 24 21 48 8d 44 24 21 48 89 84 24 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_GFT_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f c9 49 8d 8c 24 12 08 43 f3 41 0f 92 c1 8a 4c 24 07 44 8b cc eb 28 00 8b 1b 7e 8d 62 ae b9 90 01 04 d1 4a 8d 34 bd 00 00 00 00 44 89 4c 24 09 44 8b 4c 24 0e 87 4c 24 07 4c 87 ce eb bd 90 00 } //02 00 
		$a_03_1 = {00 01 00 b1 54 01 00 19 2d 90 01 04 01 00 d1 a8 01 00 56 1a 15 90 01 04 00 77 76 01 00 30 75 01 00 d4 bc 90 01 04 01 00 7a 99 90 00 } //01 00 
		$a_01_2 = {2e 73 65 64 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}