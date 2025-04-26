
rule Trojan_Win32_Gozi_BB_MTB{
	meta:
		description = "Trojan:Win32/Gozi.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {b9 04 00 00 00 6b d1 14 b8 04 00 00 00 6b c8 06 [0-15] 81 fa dc 02 00 00 } //1
		$a_81_1 = {44 72 69 76 65 2e 64 6c 6c } //1 Drive.dll
		$a_81_2 = {43 6c 6f 63 6b 63 6f 6e 64 69 74 69 6f 6e } //1 Clockcondition
		$a_81_3 = {44 6f 67 77 68 65 6e } //1 Dogwhen
		$a_81_4 = {53 69 6e 67 } //1 Sing
		$a_81_5 = {57 68 6f 6c 65 67 72 61 79 } //1 Wholegray
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Gozi_BB_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 63 2b c2 03 ce 83 c0 63 03 c1 a3 ?? ?? ?? ?? a0 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 c8 2a 44 24 10 2b d1 03 da b9 ea 26 00 00 89 1d ?? ?? ?? ?? 04 07 8b 1d ?? ?? ?? ?? 8b b4 3b a4 e8 ff ff 66 39 0d ?? ?? ?? ?? 75 19 0f b7 cd 0f b6 d0 2b d1 8b 0d ?? ?? ?? ?? 83 c1 63 03 ca 89 0d ?? ?? ?? ?? 81 c6 38 84 0b 01 0f b6 c8 89 35 ?? ?? ?? ?? 66 83 c1 63 89 b4 3b a4 e8 ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}