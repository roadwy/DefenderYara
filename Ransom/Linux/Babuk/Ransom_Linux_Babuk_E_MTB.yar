
rule Ransom_Linux_Babuk_E_MTB{
	meta:
		description = "Ransom:Linux/Babuk.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {48 8b 45 f0 48 83 c0 13 48 8d 15 aa ae 0b 00 48 89 d6 48 89 c7 e8 3c ef ff ff 85 c0 0f 84 fe 00 00 00 48 8b 45 f0 48 83 c0 13 48 8d 15 9b ae 0b 00 48 89 d6 48 89 c7 e8 9a ee ff ff 48 85 c0 0f 85 bd 00 00 00 8b 05 7b 07 0f 00 83 c0 01 89 05 72 07 0f 00 48 8b 55 c8 48 8b 45 d8 48 89 d6 48 89 c7 e8 af ed ff ff 48 8b 45 d8 48 89 c7 e8 43 ef ff ff 48 89 c2 48 8b 45 d8 48 01 d0 66 c7 00 2f 00 48 8b 45 f0 48 8d 50 13 48 8b 45 d8 48 89 d6 48 89 c7 e8 fd ed ff ff 48 8b 45 d8 48 89 c7 e8 11 ef ff ff 48 83 c0 01 48 89 c7 e8 e5 a6 02 00 48 89 45 f8 48 8b 55 d8 48 8b 45 f8 48 89 d6 48 89 c7 e8 4e ed ff ff 48 8b 45 f8 48 89 c6 48 8d 05 ff ad 0b 00 48 89 c7 b8 00 00 00 00 } //01 00 
		$a_01_1 = {2f 70 61 74 68 2f 74 6f 2f 62 65 2f 65 6e 63 72 79 70 74 65 64 } //01 00  /path/to/be/encrypted
		$a_01_2 = {62 65 73 74 77 61 79 34 75 40 6d 61 69 6c 66 65 6e 63 65 2e 63 6f 6d } //01 00  bestway4u@mailfence.com
		$a_01_3 = {62 65 73 74 77 61 79 34 75 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00  bestway4u@onionmail.com
		$a_01_4 = {43 79 6c 61 6e 63 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //00 00  Cylance Ransomware
	condition:
		any of ($a_*)
 
}