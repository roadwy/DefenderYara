
rule Trojan_BAT_FormBook_ABT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {0b 14 0c 1e 8d 90 01 03 01 0d 28 90 01 03 06 13 04 11 04 16 09 16 1e 28 90 01 03 0a 00 07 09 6f 90 01 03 0a 00 07 18 6f 90 01 03 0a 00 07 6f 90 01 03 0a 13 05 11 05 06 16 06 8e 69 6f 90 01 03 0a 0c 08 90 00 } //01 00 
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {59 00 35 00 74 00 46 00 76 00 55 00 38 00 45 00 59 00 } //00 00  Y5tFvU8EY
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_ABT_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 3d 00 00 00 1c 00 00 00 45 00 00 00 9c 00 00 00 c3 00 00 00 3f 00 00 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {4d 4e 56 4a 44 46 48 4a 44 46 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  MNVJDFHJDF.Properties.Resources.resources
		$a_01_4 = {24 61 36 38 39 62 66 30 63 2d 63 65 62 36 2d 34 38 39 35 2d 38 37 32 30 2d 65 65 62 33 34 36 35 35 33 36 65 66 } //01 00  $a689bf0c-ceb6-4895-8720-eeb3465536ef
		$a_01_5 = {43 6f 6e 66 75 73 65 72 } //00 00  Confuser
	condition:
		any of ($a_*)
 
}