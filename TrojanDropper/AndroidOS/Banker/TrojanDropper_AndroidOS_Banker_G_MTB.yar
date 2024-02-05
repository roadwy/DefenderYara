
rule TrojanDropper_AndroidOS_Banker_G_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_00_0 = {14 03 59 ee 1c 2d 14 04 dc 5a f3 0c 12 05 35 a5 2b 00 14 03 f0 ba 01 00 91 03 04 03 48 06 00 05 13 07 3c 00 b3 37 d8 07 07 5f b1 47 dc 04 05 02 48 04 02 04 14 08 cf 81 0b 00 92 03 03 08 d0 33 d6 89 b0 73 b7 64 8d 44 4f 04 01 05 14 04 66 2d 0d 00 92 04 04 03 b0 74 d8 05 05 01 01 49 01 34 01 93 28 d6 14 0a d4 8e 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}