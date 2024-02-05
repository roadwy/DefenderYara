
rule TrojanSpy_AndroidOS_SmsThief_QB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.QB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 63 72 65 74 41 63 74 69 76 69 74 79 } //01 00 
		$a_03_1 = {36 32 0c 00 22 00 84 00 90 02 05 08 02 50 00 6e 10 90 02 05 00 00 0c 00 11 00 49 04 05 03 dc 00 03 05 2b 00 16 00 00 00 01 10 b7 40 8e 00 50 00 05 03 d8 00 03 01 01 03 90 02 05 13 00 23 00 90 02 05 12 30 90 02 05 13 00 69 00 90 02 05 01 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}