
rule TrojanSpy_AndroidOS_Hydra_B{
	meta:
		description = "TrojanSpy:AndroidOS/Hydra.B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 21 24 00 14 04 59 1a 03 00 b0 a5 b1 45 b0 95 48 04 03 01 14 07 49 b7 0c 00 dc 07 01 03 48 07 00 07 14 08 b3 33 0b 00 b1 58 b0 98 b7 74 8d 44 4f 04 06 01 14 04 ce 34 08 00 b0 58 b1 48 90 0a 08 09 d8 } //01 00 
		$a_01_1 = {14 04 bc f0 09 00 14 05 b1 16 02 00 90 07 0a 09 b0 47 b1 57 92 0a 0a 09 b0 7a 14 04 3f 64 06 00 90 05 0a 09 b0 45 b1 75 b3 59 b0 a9 } //00 00 
	condition:
		any of ($a_*)
 
}