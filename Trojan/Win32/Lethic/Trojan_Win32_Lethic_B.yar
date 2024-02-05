
rule Trojan_Win32_Lethic_B{
	meta:
		description = "Trojan:Win32/Lethic.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 c1 8b 4d 08 88 01 8b 55 fc 83 c2 01 89 55 fc a1 } //01 00 
		$a_01_1 = {6a 07 8b 55 08 83 c2 0c 52 ff 15 } //01 00 
		$a_03_2 = {8b 4d 08 89 41 38 68 90 01 04 8b 55 90 01 01 52 ff 15 90 00 } //01 00 
		$a_03_3 = {8d 8c 01 f8 00 00 00 89 4d f8 68 90 01 04 8b 55 f8 52 e8 90 01 04 85 c0 74 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}