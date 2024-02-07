
rule Trojan_BAT_Lazy_ABLN_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ABLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {06 0b 07 07 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 25 06 16 06 8e 69 6f 90 01 01 00 00 0a 0c 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 2a 90 0a 3c 00 02 28 90 01 01 00 00 0a 0a 28 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_3 = {44 65 63 72 79 70 74 68 6f 6f 6b } //01 00  Decrypthook
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}