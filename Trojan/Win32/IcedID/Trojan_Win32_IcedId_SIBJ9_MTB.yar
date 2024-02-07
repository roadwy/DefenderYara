
rule Trojan_Win32_IcedId_SIBJ9_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ9!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 6f 74 69 63 65 77 65 61 74 68 65 72 5c 4f 62 73 65 72 76 65 2e 70 64 62 } //01 00  Noticeweather\Observe.pdb
		$a_03_1 = {89 37 83 c7 04 ff 4c 24 90 01 01 90 02 0a 90 18 90 02 40 8b 37 90 02 30 81 c6 90 01 04 89 37 83 c7 04 ff 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedId_SIBJ9_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ9!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 69 65 72 61 6e 67 65 2e 70 64 62 } //01 00  Tierange.pdb
		$a_03_1 = {83 c2 04 83 6c 24 90 01 01 01 89 54 24 90 01 01 90 02 10 90 18 90 02 b0 8b 44 24 90 1b 01 90 02 10 8b 00 90 02 10 89 44 24 90 01 01 90 02 ba 8b 54 24 90 1b 01 90 02 0a 8b 44 24 90 1b 08 90 02 0a 05 60 34 2f 01 90 02 0a 89 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}