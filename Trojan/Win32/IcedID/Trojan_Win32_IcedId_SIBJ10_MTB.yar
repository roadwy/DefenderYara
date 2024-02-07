
rule Trojan_Win32_IcedId_SIBJ10_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ10!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 6c 6c 53 68 6f 70 5c 45 78 61 63 74 2e 70 64 62 } //01 00  AllShop\Exact.pdb
		$a_03_1 = {83 c6 04 8b 90 02 20 81 fe 90 01 04 73 90 01 01 90 02 10 90 18 90 02 70 a1 90 01 04 90 02 10 8b bc 30 90 01 04 90 02 10 a1 90 1b 06 90 02 10 81 c7 90 01 04 90 02 0a 89 bc 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedId_SIBJ10_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ10!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 69 6c 6b 50 69 65 63 65 2e 70 64 62 } //01 00  MilkPiece.pdb
		$a_03_1 = {83 c1 04 89 4d 90 01 01 81 7d 90 1b 00 90 01 04 0f 83 90 01 04 90 08 8a 01 8b 15 90 01 04 03 55 90 1b 00 8b 82 90 01 04 a3 90 01 04 90 02 dc 8b 0d 90 1b 08 81 c1 90 01 04 89 0d 90 1b 08 8b 15 90 1b 05 03 55 90 1b 00 a1 90 1b 08 89 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}