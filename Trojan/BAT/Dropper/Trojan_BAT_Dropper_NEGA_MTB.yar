
rule Trojan_BAT_Dropper_NEGA_MTB{
	meta:
		description = "Trojan:BAT/Dropper.NEGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 09 07 5d 17 6f 90 01 03 0a 6f 90 01 03 0a 16 93 13 0c 11 0b 09 11 0c 28 90 01 03 0a 9e 11 0a 09 09 9e 12 03 28 90 01 03 0a 09 17 da 28 90 01 03 0a 26 00 09 20 ff 00 00 00 fe 02 16 fe 01 13 12 11 12 2d bb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}