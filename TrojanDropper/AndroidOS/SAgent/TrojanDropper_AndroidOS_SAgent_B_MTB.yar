
rule TrojanDropper_AndroidOS_SAgent_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 50 61 63 6b 61 67 65 4e 61 6d 65 } //01 00 
		$a_01_1 = {6c 69 73 74 46 69 6c 65 73 } //01 00 
		$a_00_2 = {35 32 12 00 34 40 03 00 01 10 48 05 07 02 48 06 08 00 b7 65 8d 55 4f 05 07 02 d8 02 02 01 d8 00 00 01 28 ef } //01 00 
		$a_00_3 = {35 20 12 00 34 31 03 00 12 01 48 04 06 00 48 05 07 01 b7 54 8d 44 4f 04 06 00 d8 00 00 01 d8 01 01 01 28 ef } //00 00 
	condition:
		any of ($a_*)
 
}