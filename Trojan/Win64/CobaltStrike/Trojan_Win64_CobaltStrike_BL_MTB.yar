
rule Trojan_Win64_CobaltStrike_BL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 85 f6 74 26 41 8a 44 2c 10 48 8b bc 24 88 00 00 00 32 84 33 e8 03 00 00 48 ff c6 83 e6 0f 88 44 2f 10 48 ff c5 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_BL_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c6 48 ff c6 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b c2 0f b6 44 04 ?? 41 30 43 ?? 48 ff c9 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_BL_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? 39 c3 7e ?? 48 89 c2 83 e2 ?? 8a 14 17 32 14 06 88 14 01 48 ff c0 eb } //1
		$a_03_1 = {41 89 d0 42 80 3c 01 ?? 74 ?? 41 89 c1 46 0f b7 04 01 ff c2 41 c1 c9 ?? 45 01 c8 44 31 c0 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_BL_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 d2 0f b7 01 [0-04] 66 2b ?? ?? ?? ?? ?? [0-04] 66 f7 [0-09] 88 06 [0-04] 46 [0-04] 43 [0-04] 83 c1 02 } //1
		$a_03_1 = {33 d2 0f b7 01 [0-04] 66 2b ?? ?? ?? ?? ?? [0-04] 66 f7 [0-09] 88 06 [0-04] 46 [0-04] 43 [0-04] 83 c1 02 [0-04] 4f 8b d7 85 fa 75 } //10
		$a_01_2 = {41 55 54 4f } //1 AUTO
		$a_01_3 = {21 54 68 69 73 20 69 73 20 61 20 57 69 6e 64 6f 77 73 20 4e 54 20 77 69 6e 64 6f 77 65 64 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 } //1 !This is a Windows NT windowed dynamic link library
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}