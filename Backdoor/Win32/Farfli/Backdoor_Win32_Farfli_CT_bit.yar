
rule Backdoor_Win32_Farfli_CT_bit{
	meta:
		description = "Backdoor:Win32/Farfli.CT!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 03 8d 90 01 02 ff ff 0f be 11 0f be 85 90 01 02 ff ff 2b d0 8b 4d fc 03 8d 90 01 02 ff ff 88 11 8b 55 fc 03 95 90 01 02 ff ff 0f be 02 0f be 8d 90 01 02 ff ff 33 c1 8b 55 fc 03 95 90 01 02 ff ff 88 02 eb a1 90 00 } //01 00 
		$a_03_1 = {ff 47 c6 85 90 01 02 ff ff 65 c6 85 90 01 02 ff ff 74 c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 6e c6 85 90 01 02 ff ff 67 90 00 } //01 00 
		$a_03_2 = {8b 4d 08 03 4d f8 8a 55 f8 88 11 8b 45 f8 33 d2 f7 75 10 8b 45 0c 33 c9 8a 0c 10 8b 55 f8 89 8c 95 90 01 02 ff ff eb c7 90 00 } //01 00 
		$a_03_3 = {81 3a 50 45 00 00 74 07 33 c0 e9 90 01 03 00 6a 04 68 00 20 00 00 8b 45 90 01 01 8b 48 90 01 01 51 8b 55 90 01 01 8b 42 34 50 ff 15 90 01 03 00 90 00 } //01 00 
		$a_03_4 = {ff 4d c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 7a c6 85 90 01 02 ff ff 69 c6 85 90 01 02 ff ff 6c c6 85 90 01 02 ff ff 6c c6 85 90 01 02 ff ff 61 c6 85 90 01 02 ff ff 2f c6 85 90 01 02 ff ff 34 c6 85 90 01 02 ff ff 2e c6 85 90 01 02 ff ff 30 c6 85 90 01 02 ff ff 20 c6 85 90 01 02 ff ff 28 c6 85 90 01 02 ff ff 63 c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 6d c6 85 90 01 02 ff ff 70 c6 85 90 01 02 ff ff 61 c6 85 90 01 02 ff ff 74 c6 85 90 01 02 ff ff 69 c6 85 90 01 02 ff ff 62 c6 85 90 01 02 ff ff 6c c6 85 90 01 02 ff ff 65 c6 85 90 01 02 ff ff 29 c6 85 90 01 02 ff ff 00 90 00 } //01 00 
		$a_03_5 = {ff 4b c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 74 c6 85 90 01 02 ff ff 68 c6 85 90 01 02 ff ff 65 c6 85 90 01 02 ff ff 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}