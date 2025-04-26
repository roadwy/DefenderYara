
rule TrojanDropper_AndroidOS_Banker_AN_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AN!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 08 36 00 d1 42 11 24 48 04 03 08 d0 66 d0 1a dc 09 08 03 48 09 01 09 14 0a 99 90 00 00 93 0b 02 06 b0 ba 91 0b 06 0a b0 2b da 0b 0b 00 b0 4b 93 04 02 02 db 04 04 01 df 04 04 01 b0 4b b4 22 b0 2b 97 02 0b 09 8d 22 4f 02 05 08 14 02 38 02 01 00 14 04 ec 64 01 00 92 09 06 0a b0 29 90 02 09 04 d8 08 08 01 01 64 01 a6 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}