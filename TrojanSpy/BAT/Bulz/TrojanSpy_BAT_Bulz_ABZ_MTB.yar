
rule TrojanSpy_BAT_Bulz_ABZ_MTB{
	meta:
		description = "TrojanSpy:BAT/Bulz.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 fe 01 60 13 04 11 04 2c 12 72 0b 03 00 70 16 14 28 90 01 03 0a 26 38 cf 00 00 00 00 73 a1 00 00 0a 0a 06 0d 09 72 49 03 00 70 73 a2 00 00 0a 6f 90 01 03 0a 00 09 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}