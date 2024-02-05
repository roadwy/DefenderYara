
rule Trojan_Win32_Ekstak_CE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {b9 36 3c ec 90 01 01 81 c1 ff 09 d8 11 eb 90 01 01 58 33 fe ff 15 90 01 04 a1 90 01 04 8b 35 90 01 04 33 c6 33 c7 5f 3d 4e e6 40 bb 0f 84 90 01 04 e9 90 01 04 81 e9 16 64 52 57 29 c8 59 57 90 00 } //01 00 
		$a_02_1 = {b9 d2 e3 5b 84 81 e9 6e 44 93 59 81 c1 c6 14 8a 89 81 e9 a7 42 50 41 01 c8 59 29 c1 58 89 04 29 59 a1 90 01 04 3d 4e e6 40 bb 74 90 01 01 a9 00 00 ff ff 0f 85 90 00 } //02 00 
		$a_02_2 = {6a 0a 58 50 ff 75 9c 56 56 ff 15 90 01 04 50 e8 90 01 04 89 45 a0 50 e8 90 01 04 8b 45 ec 8b 08 8b 09 89 4d 98 50 51 e8 90 01 04 59 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}