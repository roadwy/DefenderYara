
rule Trojan_Win64_IcedID_AX_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 94 24 ?? ?? ?? ?? 88 04 0a e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 66 89 44 24 ?? b8 ?? ?? ?? ?? eb ?? 8b c2 8b c0 eb ?? 8b 04 24 f7 b4 24 ?? ?? ?? ?? eb ?? 8b 4c 24 ?? 33 c8 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_AX_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {42 51 79 4e 48 39 } //1 BQyNH9
		$a_01_1 = {42 50 4b 48 52 57 78 49 48 4d } //1 BPKHRWxIHM
		$a_01_2 = {43 39 68 51 64 75 57 55 61 } //1 C9hQduWUa
		$a_01_3 = {46 34 4b 51 34 41 55 48 70 51 } //1 F4KQ4AUHpQ
		$a_01_4 = {46 4f 4f 66 5a 33 69 38 } //1 FOOfZ3i8
		$a_01_5 = {79 61 74 73 64 67 68 61 73 79 67 75 64 74 61 68 6a 73 6a 64 61 73 } //1 yatsdghasygudtahjsjdas
		$a_01_6 = {47 55 4f 6d 63 58 78 4e } //1 GUOmcXxN
		$a_01_7 = {48 47 72 57 50 75 70 } //1 HGrWPup
		$a_01_8 = {4c 53 4e 42 4c 73 35 } //1 LSNBLs5
		$a_01_9 = {4f 4b 63 33 78 6f 5a 38 48 52 } //1 OKc3xoZ8HR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}