
rule Trojan_Win32_IcedId_SIBJ10_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ10!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 6c 6c 53 68 6f 70 5c 45 78 61 63 74 2e 70 64 62 } //1 AllShop\Exact.pdb
		$a_03_1 = {83 c6 04 8b [0-20] 81 fe ?? ?? ?? ?? 73 ?? [0-10] 90 18 [0-70] a1 ?? ?? ?? ?? [0-10] 8b bc 30 ?? ?? ?? ?? [0-10] a1 90 1b 06 [0-10] 81 c7 ?? ?? ?? ?? [0-0a] 89 bc 30 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ10_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ10!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 69 6c 6b 50 69 65 63 65 2e 70 64 62 } //1 MilkPiece.pdb
		$a_03_1 = {83 c1 04 89 4d ?? 81 7d 90 1b 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 90 08 8a 01 8b 15 ?? ?? ?? ?? 03 55 90 1b 00 8b 82 ?? ?? ?? ?? a3 ?? ?? ?? ?? [0-dc] 8b 0d 90 1b 08 81 c1 ?? ?? ?? ?? 89 0d 90 1b 08 8b 15 90 1b 05 03 55 90 1b 00 a1 90 1b 08 89 82 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}