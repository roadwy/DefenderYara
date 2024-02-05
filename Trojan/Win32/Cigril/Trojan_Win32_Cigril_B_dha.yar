
rule Trojan_Win32_Cigril_B_dha{
	meta:
		description = "Trojan:Win32/Cigril.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6c 00 69 00 62 00 72 00 65 00 6d 00 6f 00 74 00 65 00 2e 00 64 00 61 00 74 00 } //01 00 
		$a_03_1 = {6c 69 62 63 75 72 6c 90 02 08 2e 64 6c 6c 90 00 } //01 00 
		$a_01_2 = {c1 e9 07 81 e1 01 01 01 01 44 6b d9 1b 41 8b ca 81 e1 7f 7f 7f ff 03 c9 44 33 d9 } //01 00 
		$a_01_3 = {8b 46 18 48 8d 4e 28 33 01 41 89 06 8b 46 2c 33 46 1c 41 89 46 04 8b 46 30 33 46 20 41 89 46 08 8b 46 34 33 46 24 41 89 46 0c 49 83 c6 10 } //00 00 
	condition:
		any of ($a_*)
 
}