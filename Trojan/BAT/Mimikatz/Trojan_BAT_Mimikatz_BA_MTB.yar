
rule Trojan_BAT_Mimikatz_BA_MTB{
	meta:
		description = "Trojan:BAT/Mimikatz.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 20 00 04 00 00 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a de 0a 08 2c 06 08 6f 90 01 03 0a dc 07 6f 90 01 03 0a 0d de 14 90 00 } //01 00 
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 5f 72 65 66 6c 65 63 74 69 76 65 5f 6d 69 6d 69 6b 61 74 7a } //01 00 
		$a_81_2 = {4c 6f 61 64 4d 69 6d 69 42 79 43 6f 6d 6d 61 6e 64 } //01 00 
		$a_81_3 = {4d 69 6d 69 6b 61 74 7a 44 65 6c 65 67 61 74 65 } //01 00 
		$a_81_4 = {4c 6f 61 64 4d 69 6d 69 } //01 00 
		$a_81_5 = {6d 69 6d 69 42 79 74 65 73 } //01 00 
		$a_81_6 = {47 5a 69 70 53 74 72 65 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}