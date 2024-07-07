
rule TrojanSpy_AndroidOS_Spynote_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 10 71 10 90 01 01 01 00 00 0c 01 22 08 2a 00 6e 10 55 00 0a 00 0a 03 6e 10 57 00 0a 00 0a 04 52 95 90 01 01 00 52 96 90 01 01 00 07 82 01 b7 76 06 54 00 02 00 6e 10 56 00 08 00 0a 0a 12 0b 32 0a 06 00 71 10 90 01 01 01 0b 00 0c 01 6e 10 59 00 08 00 6e 10 56 00 08 00 0a 0a 12 30 32 0a 09 00 6e 10 5a 00 08 00 71 10 90 01 01 01 0b 00 0c 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}