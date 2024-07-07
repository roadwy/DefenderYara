
rule TrojanDropper_AndroidOS_Banker_AR_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AR!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {35 08 35 00 d1 33 11 24 48 04 01 08 d0 66 d0 1a dc 09 08 03 48 09 02 09 14 0a 99 90 00 00 93 0b 03 06 b0 ba 91 0b 06 0a b0 3b da 0b 0b 00 b0 4b 93 04 03 03 db 04 04 01 df 04 04 01 b0 4b b4 33 b0 3b 97 03 0b 09 8d 33 4f 03 05 08 14 03 38 02 01 00 14 04 ec 64 01 00 92 09 06 0a b0 39 b0 94 d8 08 08 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}