
rule TrojanSpy_AndroidOS_Spynote_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {14 05 3b a7 00 00 b0 56 48 05 03 01 d9 09 06 1f dc 0a 01 02 48 0a 07 0a da 0b 09 4e 91 0b 06 0b b1 96 b0 b6 da 06 06 00 b0 56 93 05 0b 0b db 05 05 01 df 05 05 01 b0 56 94 05 0b 0b b0 56 97 05 06 0a 8d 55 4f 05 04 01 93 05 0b 08 d8 01 01 01 } //01 00 
		$a_00_1 = {64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}