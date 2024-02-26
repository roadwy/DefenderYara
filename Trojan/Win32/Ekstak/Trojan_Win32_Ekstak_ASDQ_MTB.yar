
rule Trojan_Win32_Ekstak_ASDQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {8d 44 24 1c 50 6a ff 55 6a 01 57 ff d3 55 8b b4 24 90 01 02 00 00 56 ff 15 90 01 03 00 85 c0 0f 85 90 00 } //05 00 
		$a_03_1 = {8b f0 8d 4c 24 08 81 e6 ff 00 00 00 51 83 fe 06 57 0f 93 c0 a2 90 01 03 00 ff 15 90 01 02 4c 00 8b f8 e8 90 00 } //05 00 
		$a_03_2 = {8b f0 81 e6 ff 00 00 00 83 fe 06 0f 93 c0 a2 90 01 03 00 e8 90 01 01 ff ff ff 68 90 01 02 65 00 ff 15 90 01 02 65 00 83 fe 06 72 90 00 } //05 00 
		$a_03_3 = {5f 5e 5d b8 01 00 00 00 5b 81 c4 20 06 00 00 c2 08 00 8d 44 24 14 50 57 ff 15 90 01 02 65 00 8b 1d 90 01 02 65 00 56 8b f8 ff d3 85 ff 89 44 24 10 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}