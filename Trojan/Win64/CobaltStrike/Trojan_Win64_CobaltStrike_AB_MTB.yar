
rule Trojan_Win64_CobaltStrike_AB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f3 0f 6f 41 90 01 01 48 8d 49 90 01 01 66 0f 6f ca 66 0f ef c8 f3 0f 7f 49 90 01 01 f3 0f 6f 41 90 01 01 66 0f ef c2 f3 0f 7f 41 90 01 01 f3 0f 6f 49 90 01 01 66 0f ef ca f3 0f 7f 49 90 01 01 66 0f 6f ca f3 0f 6f 41 90 01 01 66 0f ef c8 f3 0f 7f 49 90 01 01 49 83 ee 90 00 } //01 00 
		$a_03_1 = {41 8b c1 4d 8d 40 01 99 41 ff c1 f7 ff 48 63 c2 0f b6 4c 04 90 01 01 41 30 48 ff 49 83 ea 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 8b f1 ff ff ba 6f 80 e5 67 48 8b cb 48 89 05 04 26 03 00 e8 77 f1 ff ff ba eb 62 6b c2 48 8b ce 48 89 05 10 26 03 00 } //01 00 
		$a_01_1 = {4c 2b d0 8b c5 41 0f af c0 4d 69 d2 d0 00 00 00 41 0f af c0 48 98 48 2b d8 41 8b c1 } //01 00 
		$a_01_2 = {41 0f af c4 48 63 c8 49 63 c5 48 2b d9 48 2b d8 49 63 c1 48 2b d8 49 2b d8 49 03 df 48 03 df 48 8d 04 5b 48 c1 e0 06 4b 03 } //01 00 
		$a_01_3 = {f7 d8 48 98 4c 03 c0 49 8d 44 24 03 49 0f af c6 4c 03 c0 41 8b c5 f7 d8 48 63 c8 8b 05 eb 0c 03 00 f7 d8 } //01 00 
		$a_01_4 = {44 89 64 24 28 48 8b de c7 44 24 20 40 00 00 00 41 ff d2 eb 1a 41 b9 40 00 00 00 41 b8 00 30 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}