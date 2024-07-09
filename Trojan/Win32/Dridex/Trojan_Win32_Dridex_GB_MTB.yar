
rule Trojan_Win32_Dridex_GB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 32 00 cc [0-04] cc [0-04] cc } //10
		$a_80_1 = {6c 6c 6f 73 65 77 77 71 2e 6c 6c } //llosewwq.ll  2
		$a_80_2 = {2e 70 64 62 } //.pdb  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=10
 
}
rule Trojan_Win32_Dridex_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_00_0 = {89 74 24 0c 89 4c 24 08 89 54 24 04 8d 65 f4 } //1
		$a_02_1 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } //10
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  10
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=21
 
}
rule Trojan_Win32_Dridex_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 23 00 cc cc } //10
		$a_80_1 = {6c 6c 6f 73 65 77 77 71 2e 6c 6c } //llosewwq.ll  5
		$a_02_2 = {0f b6 f8 29 fb 88 65 ?? 88 d8 88 45 ?? 8b 7d ?? 8a 45 ?? 8b 5d ?? c6 45 ?? ?? 88 04 1f 89 75 } //5
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_02_2  & 1)*5) >=10
 
}
rule Trojan_Win32_Dridex_GB_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {6f c6 44 24 ?? 63 c6 44 24 ?? 00 8a 84 24 ?? 00 00 00 88 84 24 ?? 00 00 00 c6 84 24 ?? 00 00 00 58 89 54 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 66 8b 5c 24 ?? 66 89 9c 24 ?? 00 00 00 89 04 24 89 54 24 ?? e8 } //10
		$a_02_1 = {72 c6 44 24 ?? 6e 8a 74 24 ?? 80 f6 ?? 88 b4 24 ?? 00 00 00 80 f1 ?? 88 54 24 ?? c6 44 24 ?? 6c 66 8b 74 24 1c } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}