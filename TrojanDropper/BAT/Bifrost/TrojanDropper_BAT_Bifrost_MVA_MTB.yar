
rule TrojanDropper_BAT_Bifrost_MVA_MTB{
	meta:
		description = "TrojanDropper:BAT/Bifrost.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 35 00 00 70 09 28 2c 00 00 0a 28 2d 00 00 0a 6f 27 00 00 0a 74 0a 00 00 1b } //00 00 
	condition:
		any of ($a_*)
 
}