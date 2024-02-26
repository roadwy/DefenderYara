
rule TrojanSpy_BAT_Noon_SX_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 07 6f 0d 00 00 0a 03 58 20 00 01 00 00 5d 0c 08 16 2f 08 08 20 00 01 00 00 58 0c 06 07 08 d1 9d 07 17 58 0b 07 02 6f 0c 00 00 0a 32 d2 } //00 00 
	condition:
		any of ($a_*)
 
}