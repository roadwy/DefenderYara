
rule Trojan_Win32_IcedId_SIBN_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 69 76 69 73 69 6f 6e 2e 70 64 62 } //01 00  Division.pdb
		$a_03_1 = {83 c5 04 8b 90 02 10 81 fd 90 01 04 73 90 01 01 90 02 20 90 18 90 02 a5 8b 3d 90 01 04 90 02 0a 8b b4 2f 90 01 04 90 02 30 81 c6 90 01 04 90 02 20 89 b4 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedId_SIBN_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 65 65 70 56 6f 69 63 65 5c 77 65 6e 74 6c 6f 74 48 61 69 72 2e 70 64 62 } //01 00  keepVoice\wentlotHair.pdb
		$a_03_1 = {83 c7 04 0f 90 02 10 89 7c 24 90 01 01 90 02 10 83 6c 24 28 01 90 18 90 02 95 8b 54 24 90 1b 01 90 02 10 8b 12 90 02 10 81 c2 90 01 04 90 02 10 89 15 90 01 04 90 02 80 8b 7c 24 90 1b 01 90 02 10 a1 90 1b 0a 90 02 10 89 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}