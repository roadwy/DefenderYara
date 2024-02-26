
rule Trojan_BAT_Nanocore_ABDB_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 07 6f 90 01 03 0a 6f 90 01 03 0a 0c 07 08 14 6f 90 01 03 0a 26 2a 90 0a 33 00 28 90 01 03 0a 28 90 01 03 06 28 90 01 03 0a 6f 90 01 03 0a 0a 06 6f 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}