
rule TrojanDropper_AndroidOS_Banker_O_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 02 12 03 90 01 06 0a 02 12 f4 32 42 16 00 39 02 03 00 28 12 b1 29 12 04 35 24 0b 00 48 05 01 04 b7 a5 8d 55 4f 05 01 04 d8 04 04 01 28 f6 90 01 06 28 e1 90 00 } //01 00 
		$a_02_1 = {76 69 63 65 3b 90 09 06 00 2f 90 01 02 53 65 72 90 00 } //01 00 
		$a_02_2 = {63 61 74 69 6f 6e 3b 90 09 08 00 2f 90 01 02 41 70 70 6c 69 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 47 } //bb 04 
	condition:
		any of ($a_*)
 
}