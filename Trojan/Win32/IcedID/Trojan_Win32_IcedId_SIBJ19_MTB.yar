
rule Trojan_Win32_IcedId_SIBJ19_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ19!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 77 69 6d 2e 70 64 62 } //01 00 
		$a_03_1 = {04 ff 4c 24 90 01 01 90 02 10 8b 15 90 01 04 89 11 90 18 90 02 60 8b 44 24 90 01 01 90 02 10 8b 00 90 02 10 a3 90 1b 02 90 02 e0 81 05 90 1b 02 90 01 04 90 02 10 8b 4c 24 90 01 01 83 44 24 90 01 01 04 ff 4c 24 90 01 01 90 02 10 8b 15 90 1b 02 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}