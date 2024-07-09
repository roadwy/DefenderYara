
rule Trojan_Win32_IcedId_SIBJ13_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 68 69 65 66 4c 65 67 2e 70 64 62 } //1 chiefLeg.pdb
		$a_03_1 = {89 3e 83 c6 04 [0-10] 83 6c 24 ?? 01 89 74 24 ?? 90 18 [0-60] 8b 54 24 90 1b 02 8b 3a [0-50] 8b 74 24 90 1b 02 81 c7 ?? ?? ?? ?? [0-10] 89 3e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ13_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 74 6f 6f 64 2e 70 64 62 } //1 stood.pdb
		$a_03_1 = {83 c5 04 0f [0-10] 81 fd ?? ?? ?? ?? 73 ?? [0-10] 90 18 [0-60] 8b 3d ?? ?? ?? ?? [0-20] 8b b4 2f ?? ?? ?? ?? [0-30] 81 c6 ?? ?? ?? ?? [0-10] 89 b4 ?? ?? ?? ?? [0-10] 83 c5 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}