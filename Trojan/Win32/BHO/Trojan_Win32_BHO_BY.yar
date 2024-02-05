
rule Trojan_Win32_BHO_BY{
	meta:
		description = "Trojan:Win32/BHO.BY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 69 63 72 6f 73 6f 66 74 5f 6c 6f 63 6b 00 } //01 00 
		$a_01_1 = {89 45 08 8b d0 8a 04 0e 32 45 10 88 01 41 ff 4d 08 75 f2 88 1c 3a } //01 00 
		$a_01_2 = {bb 68 01 00 00 eb 13 bb e8 01 00 00 eb 0c bb 70 01 00 00 eb 05 bb f0 01 00 00 bf 9f 86 01 00 } //01 00 
		$a_03_3 = {6a 3c 50 68 08 d0 04 00 ff 75 f8 ff 15 90 01 04 85 c0 74 45 80 bd 90 01 02 ff ff 00 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}