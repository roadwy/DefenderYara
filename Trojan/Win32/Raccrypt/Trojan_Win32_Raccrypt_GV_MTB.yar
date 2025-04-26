
rule Trojan_Win32_Raccrypt_GV_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 [0-0a] 90 17 02 01 01 31 33 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bd a3 53 78 c7 84 24 ?? ?? ?? ?? ?? ?? c4 0d c7 84 24 ?? ?? ?? ?? c5 00 1d 75 c7 84 24 ?? ?? ?? ?? 84 50 74 21 c7 84 24 ?? ?? ?? ?? 08 d3 e3 58 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b [0-0a] c1 ?? 04 03 [0-1e] c1 [0-01] 05 03 [0-0f] 90 17 02 01 01 31 33 [0-0a] 8b 45 ?? 29 45 [0-0f] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 6a 40 ff 35 90 0a 96 00 6c c6 05 ?? ?? ?? ?? 6c [0-06] c6 05 ?? ?? ?? ?? 6b [0-07] c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 33 [0-07] ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 } //1
		$a_01_1 = {01 08 c3 29 08 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 eb 34 ef c6 c3 } //1
		$a_01_1 = {01 08 c3 29 08 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}