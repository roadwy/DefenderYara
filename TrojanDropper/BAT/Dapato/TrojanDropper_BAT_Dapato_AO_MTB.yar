
rule TrojanDropper_BAT_Dapato_AO_MTB{
	meta:
		description = "TrojanDropper:BAT/Dapato.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 fb 00 00 70 6f 90 01 03 0a 2c 1a 02 72 fb 00 00 70 28 3d 00 00 0a 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}