
rule Ransom_Win32_Trenalt_A{
	meta:
		description = "Ransom:Win32/Trenalt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 00 00 01 00 8d 85 f0 ff fe ff 8a 0d 4c f6 40 00 00 08 40 4a 75 f4 8d 95 f0 ff fe ff 8b 4d f8 8b c3 e8 fc 9b ff ff } //01 00 
		$a_03_1 = {2e 6d 73 67 00 90 01 0b 2e 65 6d 6c 00 90 01 0b 2e 6d 64 62 00 90 01 0b 2e 75 72 6c 00 90 01 0b 2e 62 61 74 00 90 01 0b 2e 63 66 67 00 90 01 0b 2e 70 67 70 00 90 01 0b 2e 70 61 73 00 90 01 0b 2e 64 70 72 00 90 01 0b 2e 64 66 6d 00 90 00 } //01 00 
		$a_01_2 = {6c 6e 74 65 72 6e 61 74 00 } //01 00 
		$a_03_3 = {68 40 77 1b 00 6a 00 6a 00 e8 90 01 04 8b f0 eb 0c 53 e8 90 00 } //01 00 
		$a_01_4 = {43 80 fb 7b 75 9d 33 c0 5a 59 59 64 89 10 68 } //00 00 
		$a_00_5 = {5d 04 00 } //00 9c 
	condition:
		any of ($a_*)
 
}