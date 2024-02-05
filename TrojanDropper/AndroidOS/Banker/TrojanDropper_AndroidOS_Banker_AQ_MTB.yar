
rule TrojanDropper_AndroidOS_Banker_AQ_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AQ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {35 08 35 00 d1 11 11 24 48 04 02 08 d0 55 d0 1a dc 09 08 03 48 09 06 09 14 0a 99 90 00 00 93 0b 01 05 b0 ba 91 0b 05 0a b0 1b da 0b 0b 00 b0 4b 93 04 01 01 db 04 04 01 df 04 04 01 b0 4b b4 11 b0 1b 97 01 0b 09 8d 11 4f 01 03 08 14 01 38 02 01 00 14 04 ec 64 01 00 92 09 05 0a b0 19 b0 94 d8 08 08 01 01 51 01 a5 } //00 00 
	condition:
		any of ($a_*)
 
}