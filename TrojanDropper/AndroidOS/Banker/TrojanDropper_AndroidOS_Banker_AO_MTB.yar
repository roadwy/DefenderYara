
rule TrojanDropper_AndroidOS_Banker_AO_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AO!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {35 39 33 00 d1 11 11 24 48 07 02 09 d0 44 d0 1a dc 0b 09 03 48 0b 08 0b 14 0c 99 90 00 00 93 0d 01 04 b0 dc 91 0d 04 0c b0 1d da 0d 0d 00 b0 7d 93 07 01 01 b3 07 b7 07 b0 7d b4 11 b0 1d 97 01 0d 0b 8d 11 4f 01 06 09 14 01 38 02 01 00 14 07 ec 64 01 00 92 0b 04 0c b0 1b b0 b7 d8 09 09 01 01 41 01 c4 28 ce } //01 00 
		$a_00_1 = {4c 64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 3b } //00 00  Ldalvik/system/DexClassLoader;
	condition:
		any of ($a_*)
 
}