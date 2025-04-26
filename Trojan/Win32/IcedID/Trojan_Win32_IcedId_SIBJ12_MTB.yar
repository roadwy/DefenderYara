
rule Trojan_Win32_IcedId_SIBJ12_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 6e 63 6c 75 64 65 62 6c 75 65 5c 63 68 61 72 74 2e 70 64 62 } //1 includeblue\chart.pdb
		$a_03_1 = {83 c6 04 2c [0-0a] 81 fe ?? ?? ?? ?? [0-0a] 90 18 [0-70] 8b 2d ?? ?? ?? ?? [0-20] 8b bc 2e ?? ?? ?? ?? [0-30] 81 c7 ?? ?? ?? ?? [0-10] 89 bc 2e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ12_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 75 64 6d 69 6e 65 2e 70 64 62 } //1 Loudmine.pdb
		$a_03_1 = {03 cd 89 4c 24 ?? 8b 29 [0-30] 8b 4c 24 90 1b 00 81 c5 ?? ?? ?? ?? [0-10] 89 29 [0-30] 8b 6c 24 ?? [0-10] 83 c5 04 [0-10] 89 6c 24 90 1b 06 [0-10] 81 fd ?? ?? ?? ?? 0f 82 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ12_MTB_3{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {67 00 75 00 6e 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00 } //1 guncorrect.exe
		$a_03_1 = {4d 85 ff 74 ?? b8 ?? ?? ?? ?? [0-0a] 8b 15 ?? ?? ?? ?? 8b 8c 02 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? [0-0a] 89 8c 02 90 1b 04 83 c0 04 3d ?? ?? ?? ?? 72 ?? [0-20] 4f [0-10] 73 ?? [0-0a] 83 ff ?? 77 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}