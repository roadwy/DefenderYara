
rule TrojanSpy_BAT_Stealergen_MD_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e 69 1e 5a 90 0a 0c 00 06 02 7b 90 01 03 04 90 02 05 6f 90 01 03 0a 06 02 7b 90 01 03 04 6f 90 01 03 0a 06 02 7b 90 01 03 04 8e 69 1e 5a 6f 90 01 03 0a 06 02 7b 90 01 03 04 6f 90 01 03 0a 06 6f 90 01 03 0a 0b 03 73 90 01 03 0a 0c 08 07 16 73 90 01 03 0a 0d 03 8e 69 17 59 17 58 8d 90 01 01 00 00 01 13 04 09 11 04 16 03 8e 69 6f 90 01 03 0a 13 05 11 04 11 05 28 90 01 03 2b 28 90 01 03 2b 13 06 de 90 00 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_81_2 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_81_3 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_6 = {63 69 70 68 65 72 } //01 00  cipher
		$a_81_7 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_8 = {73 65 74 5f 4b 65 79 } //01 00  set_Key
		$a_81_9 = {73 65 74 5f 49 56 } //01 00  set_IV
		$a_81_10 = {73 65 74 5f 42 6c 6f 63 6b 53 69 7a 65 } //01 00  set_BlockSize
		$a_81_11 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}