
rule Trojan_Win32_Formbook_AB_MTB{
	meta:
		description = "Trojan:Win32/Formbook.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 17 8a ca 32 c2 2a c8 80 c1 14 c0 c9 02 32 ca 2a ca f6 d1 32 ca 02 ca f6 d1 80 c1 37 32 ca 88 0c 17 42 3b d3 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Formbook_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? c7 45 ?? ?? ?? ?? ?? 8b 55 ?? 8b 4d ?? d3 ea 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 2b 45 ?? 89 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Formbook_AB_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.AB!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {71 00 68 00 6a 00 20 00 5a 00 74 00 75 00 51 00 68 00 61 00 3b 00 6a 00 64 00 66 00 6e 00 5b 00 69 00 61 00 65 00 74 00 72 00 } //1 qhj ZtuQha;jdfn[iaetr
		$a_01_1 = {73 42 73 70 4b 42 73 } //1 sBspKBs
		$a_01_2 = {47 73 38 4c 48 73 7a 4a 48 73 } //1 Gs8LHszJHs
		$a_01_3 = {43 44 73 61 43 44 73 39 67 44 73 } //1 CDsaCDs9gDs
		$a_01_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_01_5 = {68 74 74 70 3a 2f 2f 6d 65 6d 62 65 72 73 2e 78 6f 6f 6d 2e 63 6f 6d 2f 64 65 76 73 66 6f 72 74 2f 69 6e 64 65 78 2e 68 74 6d 6c } //1 http://members.xoom.com/devsfort/index.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}