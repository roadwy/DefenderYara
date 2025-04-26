
rule TrojanDropper_AndroidOS_SAgnt_M_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 75 11 24 48 07 03 08 d0 44 d0 1a dc 09 08 03 48 09 01 09 14 0a 99 90 00 00 93 0b 05 04 b0 ba 91 0b 04 0a b0 5b da 0b 0b 00 b0 7b 93 07 05 05 db 07 07 01 df 07 07 01 b0 7b b4 55 b0 5b 97 05 0b 09 8d 55 4f 05 06 08 14 05 38 02 01 00 14 07 ec 64 01 00 92 09 04 0a b0 59 90 05 09 07 d8 08 08 01 01 47 01 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}