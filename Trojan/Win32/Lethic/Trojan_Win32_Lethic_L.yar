
rule Trojan_Win32_Lethic_L{
	meta:
		description = "Trojan:Win32/Lethic.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 e8 61 40 00 8d 85 f0 fd ff ff 50 ff 15 4c 50 40 00 8b 4d 08 51 8d 95 f0 fd ff ff 52 e8 81 fd ff ff } //01 00 
		$a_00_1 = {68 03 01 00 00 68 00 67 40 00 8b 4d 08 81 c1 80 06 00 00 51 ff 15 20 50 40 00 6a 7f 68 64 67 40 00 8b 55 08 81 c2 88 08 00 00 52 ff 15 20 50 40 00 } //01 00 
		$a_03_2 = {51 68 11 11 11 11 8b 55 90 01 01 52 8b 85 90 01 04 50 e8 90 01 04 8b 4d 90 01 01 51 68 22 22 22 22 8b 55 90 01 01 52 8b 85 90 01 04 50 e8 90 01 04 8b 4d 90 01 01 51 68 33 33 33 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}