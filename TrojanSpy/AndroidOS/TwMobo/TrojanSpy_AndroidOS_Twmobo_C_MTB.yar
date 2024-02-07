
rule TrojanSpy_AndroidOS_Twmobo_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Twmobo.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_00_0 = {21 53 35 31 10 00 48 03 05 01 21 64 94 04 01 04 48 04 06 04 b7 43 8d 33 4f 03 02 01 d8 01 01 01 28 f0 } //01 00 
		$a_00_1 = {4e 44 5f 44 55 4d 50 } //01 00  ND_DUMP
		$a_00_2 = {63 37 66 33 66 35 64 63 61 64 38 34 65 65 61 65 61 36 34 65 34 30 64 63 61 34 61 32 65 32 66 35 } //00 00  c7f3f5dcad84eeaea64e40dca4a2e2f5
	condition:
		any of ($a_*)
 
}