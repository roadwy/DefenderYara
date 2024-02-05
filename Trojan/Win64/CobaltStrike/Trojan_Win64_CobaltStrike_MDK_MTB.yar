
rule Trojan_Win64_CobaltStrike_MDK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8d 15 89 0b 05 00 48 8b c8 48 8b f0 e8 90 02 04 48 8d 15 67 0b 05 00 48 8b ce 48 8b e8 e8 90 02 04 48 8d 15 45 0b 05 00 48 8b ce 48 8b d8 e8 90 02 04 48 8d 15 23 0b 05 00 48 8b ce 48 8b f8 e8 90 00 } //01 00 
		$a_03_1 = {48 8b 44 0a f8 4c 8b 54 0a f0 48 83 e9 90 02 01 48 89 41 18 4c 89 51 10 48 8b 44 0a 08 4c 8b 14 0a 49 ff c9 48 89 41 08 4c 89 11 75 d5 90 00 } //01 00 
		$a_03_2 = {0f b6 02 48 ff c1 48 ff ca 48 3b cf 88 44 31 90 02 01 7c ee 90 00 } //01 00 
		$a_03_3 = {48 8d 15 17 0d 05 00 48 8b c8 48 8b d8 e8 90 02 04 48 8d 15 f5 0c 05 00 48 8b cb 48 8b f0 e8 90 02 04 48 8d 15 d3 0c 05 00 48 8b cb 4c 8b f0 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}