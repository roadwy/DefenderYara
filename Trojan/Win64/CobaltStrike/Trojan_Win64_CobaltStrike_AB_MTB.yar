
rule Trojan_Win64_CobaltStrike_AB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_81_1 = {54 63 79 41 6b 71 68 34 6f 4a 58 67 56 33 57 59 79 4c 34 4b 45 66 43 4d 6b 39 57 38 6f 4a 43 70 6d 78 31 62 6f 2b 6a 56 67 4b 59 3d } //1 TcyAkqh4oJXgV3WYyL4KEfCMk9W8oJCpmx1bo+jVgKY=
		$a_81_2 = {51 4a 4d 62 68 43 53 45 48 35 72 41 75 52 78 68 2b 43 74 57 39 36 67 30 4f 72 30 46 78 61 39 49 4b 72 34 75 63 3d } //1 QJMbhCSEH5rAuRxh+CtW96g0Or0Fxa9IKr4uc=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_Win64_CobaltStrike_AB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 6f 41 90 01 01 48 8d 49 90 01 01 66 0f 6f ca 66 0f ef c8 f3 0f 7f 49 90 01 01 f3 0f 6f 41 90 01 01 66 0f ef c2 f3 0f 7f 41 90 01 01 f3 0f 6f 49 90 01 01 66 0f ef ca f3 0f 7f 49 90 01 01 66 0f 6f ca f3 0f 6f 41 90 01 01 66 0f ef c8 f3 0f 7f 49 90 01 01 49 83 ee 90 00 } //1
		$a_03_1 = {41 8b c1 4d 8d 40 01 99 41 ff c1 f7 ff 48 63 c2 0f b6 4c 04 90 01 01 41 30 48 ff 49 83 ea 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_AB_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {e8 8b f1 ff ff ba 6f 80 e5 67 48 8b cb 48 89 05 04 26 03 00 e8 77 f1 ff ff ba eb 62 6b c2 48 8b ce 48 89 05 10 26 03 00 } //1
		$a_01_1 = {4c 2b d0 8b c5 41 0f af c0 4d 69 d2 d0 00 00 00 41 0f af c0 48 98 48 2b d8 41 8b c1 } //1
		$a_01_2 = {41 0f af c4 48 63 c8 49 63 c5 48 2b d9 48 2b d8 49 63 c1 48 2b d8 49 2b d8 49 03 df 48 03 df 48 8d 04 5b 48 c1 e0 06 4b 03 } //1
		$a_01_3 = {f7 d8 48 98 4c 03 c0 49 8d 44 24 03 49 0f af c6 4c 03 c0 41 8b c5 f7 d8 48 63 c8 8b 05 eb 0c 03 00 f7 d8 } //1
		$a_01_4 = {44 89 64 24 28 48 8b de c7 44 24 20 40 00 00 00 41 ff d2 eb 1a 41 b9 40 00 00 00 41 b8 00 30 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}