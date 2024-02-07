
rule Trojan_BAT_FormBook_KWFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.KWFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e fd 01 00 04 73 cb 03 00 0a 72 90 01 03 70 6f 90 01 03 0a 74 55 01 00 1b 0a 73 cd 03 00 0a 0b 07 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 0c 73 cf 03 00 0a 0d 09 08 6f 90 01 03 0a 00 09 18 6f 90 01 03 0a 00 09 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 13 04 11 04 17 28 90 01 03 06 28 90 01 03 06 6f 90 01 03 0a 1f 0b 9a 80 fc 01 00 04 90 00 } //01 00 
		$a_01_1 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_01_2 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}