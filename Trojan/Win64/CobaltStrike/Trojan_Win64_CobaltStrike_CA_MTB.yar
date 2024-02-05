
rule Trojan_Win64_CobaltStrike_CA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 2b ce 41 ff c0 49 03 cc 02 14 39 42 32 14 90 02 02 48 8b 0d 90 01 04 49 63 c6 41 ff c6 88 14 90 02 02 49 63 c9 49 3b cb 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_CA_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 44 24 47 02 c6 44 24 48 55 } //01 00 
		$a_01_1 = {80 44 24 4a 24 c6 44 24 4b 4b } //01 00 
		$a_01_2 = {80 44 24 4f 0a c6 44 24 50 3b } //01 00 
		$a_01_3 = {80 44 24 48 11 c6 44 24 49 4a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_CA_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 d0 8b c3 ff c3 6b d2 90 01 01 2b c2 48 63 c8 48 8b 44 24 90 01 01 42 8a 8c 09 90 01 04 43 32 8c 08 90 01 04 41 88 0c 00 48 63 c3 49 ff c0 48 3b 44 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_CA_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 08 00 "
		
	strings :
		$a_01_0 = {b8 89 88 88 88 41 f7 e8 41 03 d0 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 0f 41 8b c9 2b c8 41 8d 04 4a 41 03 c0 48 63 c8 0f b6 14 31 41 32 14 24 43 8d 04 18 48 63 c8 88 14 19 41 ff c0 4d 8d 64 24 01 8b 4d af 03 cf 44 3b c1 72 } //01 00 
		$a_01_1 = {31 76 35 33 64 50 32 76 34 40 66 5a 49 3f 53 65 78 76 4c 55 35 4b 7a 37 4e 29 74 3e 67 } //01 00 
		$a_01_2 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41 } //00 00 
	condition:
		any of ($a_*)
 
}