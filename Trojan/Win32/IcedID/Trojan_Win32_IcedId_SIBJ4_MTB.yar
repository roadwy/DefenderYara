
rule Trojan_Win32_IcedId_SIBJ4_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ4!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 69 74 68 65 78 61 63 74 5c 4e 65 65 64 73 75 70 70 6f 72 74 5c 42 65 66 6f 72 65 2e 70 64 62 } //01 00 
		$a_03_1 = {8b 00 89 44 24 90 01 01 90 02 20 8b 4c 24 90 01 01 8b 44 24 90 1b 00 83 44 24 90 1b 02 04 05 90 01 04 90 02 05 89 01 90 02 10 ff 4c 24 90 01 01 90 18 90 02 7a 8b 44 24 90 1b 02 90 02 0a 8b 00 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}