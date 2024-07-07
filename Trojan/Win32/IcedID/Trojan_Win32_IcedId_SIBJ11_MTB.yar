
rule Trojan_Win32_IcedId_SIBJ11_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {65 6e 74 65 72 2e 70 64 62 } //1 enter.pdb
		$a_03_1 = {8b 0f 81 c1 90 01 04 90 02 10 89 0f 83 c7 04 83 6c 24 90 01 01 01 90 02 10 0f 85 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ11_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 72 65 61 6d 70 72 6f 76 69 64 65 2e 70 64 62 } //1 dreamprovide.pdb
		$a_03_1 = {04 ff 4c 24 90 01 01 90 02 0a 90 18 90 02 70 8b 5c 24 90 01 01 90 02 20 8b 1b 90 02 3a 8b 44 24 90 1b 04 81 c3 90 01 04 90 02 10 89 18 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ11_MTB_3{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6c 6f 6e 79 5c 65 78 63 65 70 74 2e 70 64 62 } //1 Colony\except.pdb
		$a_03_1 = {83 c1 04 ff 4c 24 90 01 01 89 4c 24 90 01 01 90 18 90 02 b0 8b 54 24 90 1b 01 90 02 20 8b 12 90 02 20 89 54 24 90 01 01 90 02 70 8b 54 24 90 1b 07 90 02 40 8b 4c 24 90 1b 01 81 c2 90 01 04 90 02 20 89 11 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}