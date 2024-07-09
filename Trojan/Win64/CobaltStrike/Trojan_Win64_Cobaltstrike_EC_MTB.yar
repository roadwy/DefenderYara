
rule Trojan_Win64_CobaltStrike_EC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 05 b0 83 f0 ?? 89 c2 8b 85 ?? ?? ?? ?? 48 98 88 54 05 b0 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ff 29 03 00 7e cf c7 85 ?? ?? ?? ?? 00 00 00 00 eb 25 8b 85 ?? ?? ?? ?? 48 98 0f b6 44 05 b0 83 f0 ?? 89 c2 8b 85 ?? ?? ?? ?? 48 98 88 54 05 b0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CobaltStrike_EC_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 40 49 03 c2 42 0f b6 0c 18 b8 ?? ?? ?? ?? 44 03 c1 48 8b 8c 24 c8 00 00 00 41 f7 e8 41 03 d0 c1 fa 0e 8b c2 c1 e8 1f 03 d0 69 d2 ?? ?? ?? ?? 44 2b c2 49 63 c0 48 2b 04 24 48 03 44 24 50 48 03 44 24 60 0f b6 04 28 30 04 0b } //1
		$a_81_1 = {6d 5e 71 26 35 6f 76 38 61 43 59 75 52 6c 29 4c 64 6b 4c 25 44 34 4b 2b 4e 56 39 66 53 28 75 62 29 3f 53 79 49 65 56 2b 25 49 35 6f 59 43 37 6c 79 65 45 58 23 56 70 4f 6d 49 65 77 71 21 67 54 } //1 m^q&5ov8aCYuRl)LdkL%D4K+NV9fS(ub)?SyIeV+%I5oYC7lyeEX#VpOmIewq!gT
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}