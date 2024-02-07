
rule Trojan_BAT_ClipBanker_VW_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.VW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 79 73 48 6f 73 74 74 } //01 00  SysHostt
		$a_81_1 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_81_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_3 = {42 69 74 44 65 63 6f 64 65 72 } //01 00  BitDecoder
		$a_81_4 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //01 00  ReverseDecode
		$a_81_5 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //01 00  LzmaDecoder
		$a_81_6 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_7 = {4c 6f 61 64 4d 6f 64 75 6c 65 } //01 00  LoadModule
		$a_81_8 = {42 6c 6f 63 6b 43 6f 70 79 } //01 00  BlockCopy
		$a_81_9 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_10 = {47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 } //01 00  GetEntryAssembly
		$a_81_11 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_12 = {52 65 61 64 42 79 74 65 } //0a 00  ReadByte
		$a_00_13 = {11 17 20 8f a0 12 fb 5a 20 29 3c 1e 84 61 } //00 00 
	condition:
		any of ($a_*)
 
}