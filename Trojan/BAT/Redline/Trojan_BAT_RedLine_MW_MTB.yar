
rule Trojan_BAT_RedLine_MW_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 1a 58 11 04 16 08 28 90 01 03 0a 28 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 7e 90 01 03 04 11 05 6f a9 00 00 0a 7e 90 01 03 04 02 6f 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 17 59 28 90 01 03 0a 16 7e 90 01 03 04 02 1a 28 90 01 03 0a 11 05 0d 90 00 } //06 00 
		$a_01_1 = {57 ff a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 dc 00 00 00 89 00 00 00 4f 01 00 00 3e 02 00 00 b5 02 } //01 00 
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 42 6c 6f 63 6b } //01 00  TransformBlock
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_5 = {43 6c 69 65 6e 74 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  ClientCredentials
		$a_01_6 = {47 65 74 44 65 63 6f 64 65 64 } //00 00  GetDecoded
	condition:
		any of ($a_*)
 
}