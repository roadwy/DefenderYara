
rule Trojan_Win32_IcedId_SIBJ_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 72 6f 6d 46 61 6c 6c 5c 77 69 66 65 2e 70 64 62 } //01 00 
		$a_03_1 = {89 08 8b c2 90 02 0a 81 7c 24 90 01 01 90 01 04 90 18 90 02 3a 8b 0d 90 01 04 81 c1 90 01 04 90 02 05 03 4c 24 90 1b 01 90 02 0a 89 4c 24 1c 8b 09 90 02 25 81 c1 90 01 04 83 44 24 90 01 01 04 90 02 10 8b 44 24 1c 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}