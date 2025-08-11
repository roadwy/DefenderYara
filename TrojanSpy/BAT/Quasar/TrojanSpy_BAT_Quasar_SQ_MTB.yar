
rule TrojanSpy_BAT_Quasar_SQ_MTB{
	meta:
		description = "TrojanSpy:BAT/Quasar.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 09 11 08 8f 75 00 00 01 25 47 11 04 11 08 58 1f 11 5a 20 00 01 00 00 5d d2 61 d2 52 11 04 1f 1f 5a 09 11 08 91 58 20 00 01 00 00 5d 13 04 11 08 17 58 13 08 11 08 09 8e 69 32 c5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}