
rule Trojan_Win32_Mooplids_A{
	meta:
		description = "Trojan:Win32/Mooplids.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0b 81 f9 47 45 54 20 74 44 81 f9 50 4f 53 54 74 3c } //01 00 
		$a_03_1 = {c6 06 6d c6 46 0c 00 c7 46 08 2e 64 6c 6c 47 e8 90 01 04 33 d2 6a 19 59 f7 f1 80 c2 61 88 14 37 47 83 ff 08 72 e8 90 00 } //01 00 
		$a_03_2 = {80 01 02 41 80 39 00 75 f7 eb 04 80 02 90 01 01 42 80 3a 00 75 f7 90 00 } //01 00 
		$a_01_3 = {0f 70 ca 01 8b 85 ec fe ff ff 03 45 fc 6a 00 6a 01 ff 75 08 ff d0 } //01 00 
		$a_01_4 = {3b 07 75 18 8b 1b 8b 43 3c b9 02 21 00 00 c7 45 f8 01 00 00 00 66 89 4c 18 16 eb 0e } //00 00 
	condition:
		any of ($a_*)
 
}