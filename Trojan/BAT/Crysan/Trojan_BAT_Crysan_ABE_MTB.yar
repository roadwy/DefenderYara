
rule Trojan_BAT_Crysan_ABE_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ABE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 00 07 2a 90 0a 22 00 00 20 1d 90 01 02 00 8d 09 90 01 02 01 25 d0 06 90 01 02 04 28 0a 90 01 02 0a 0a 06 28 03 90 01 02 06 0b 90 00 } //01 00 
		$a_03_1 = {06 16 73 05 90 01 02 0a 73 06 90 01 02 0a 0c 00 08 07 2b 03 00 2b 07 6f 07 90 01 02 0a 2b f6 90 00 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_4 = {57 72 69 74 65 42 79 74 65 } //01 00  WriteByte
		$a_01_5 = {52 65 61 64 42 79 74 65 } //00 00  ReadByte
	condition:
		any of ($a_*)
 
}