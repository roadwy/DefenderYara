
rule TrojanSpy_AndroidOS_Drinik_AB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Drinik.AB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {22 00 2e 18 70 10 90 01 04 6e 20 90 01 02 32 00 0c 02 21 23 36 34 90 01 02 21 23 12 04 35 34 90 01 02 46 01 02 04 71 10 90 01 02 01 00 0a 01 8e 11 6e 20 90 01 02 10 00 d8 04 04 01 28 f2 6e 10 90 01 02 00 00 0c 02 11 02 1a 02 00 00 11 02 90 00 } //01 00 
		$a_03_1 = {22 04 38 18 70 10 90 01 02 04 00 21 30 12 01 35 01 11 00 46 02 03 01 71 10 90 01 02 02 00 0a 02 d8 02 90 01 07 78 30 32 8e 22 6e 20 90 01 02 24 00 d8 01 01 01 28 f0 6e 10 90 01 02 04 00 0c 03 11 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}