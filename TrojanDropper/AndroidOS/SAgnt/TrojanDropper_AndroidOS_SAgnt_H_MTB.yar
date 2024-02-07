
rule TrojanDropper_AndroidOS_SAgnt_H_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 07 39 07 06 00 12 17 6e 20 90 01 01 00 76 00 22 01 90 01 01 00 70 10 90 01 01 00 01 00 23 b2 90 01 01 00 4d 0d 02 08 4d 0e 02 09 4d 01 02 0a 6e 30 90 01 01 00 36 02 0c 01 1f 01 90 01 01 00 6e 10 90 01 01 00 00 00 0c 02 6e 10 90 01 01 00 02 00 0c 02 21 05 21 16 b0 65 71 20 90 01 01 00 52 00 0c 02 1f 02 90 01 01 00 21 05 71 55 90 01 01 00 80 82 21 00 21 15 71 55 90 01 01 00 81 02 6e 30 90 01 01 00 34 02 90 00 } //01 00 
		$a_00_1 = {63 6f 6d 2f 6d 61 69 6e 2f 73 74 75 62 } //00 00  com/main/stub
	condition:
		any of ($a_*)
 
}