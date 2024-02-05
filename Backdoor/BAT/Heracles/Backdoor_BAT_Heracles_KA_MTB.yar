
rule Backdoor_BAT_Heracles_KA_MTB{
	meta:
		description = "Backdoor:BAT/Heracles.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {fe 0c 05 00 20 01 00 00 00 58 28 6a 00 00 06 28 43 00 00 0a 5d fe 0e 05 00 fe 0c 06 00 fe 0c 03 00 fe 0c 05 00 94 58 28 6b 00 00 06 28 43 00 00 0a 5d fe 0e 06 00 fe 0c 03 00 fe 0c 05 00 94 fe 0e 0d 00 fe 0c 03 00 fe 0c 05 00 fe 0c 03 00 fe 0c 06 00 94 9e fe 0c 03 00 fe 0c 06 00 fe 0c 0d 00 9e fe 0c 03 00 fe 0c 03 00 fe 0c 05 00 94 fe 0c 03 00 fe 0c 06 00 94 58 20 00 01 00 00 5d 94 fe 0e 0e 00 fe 0c 07 00 fe 0c 0c 00 fe 09 00 00 fe 0c 0c 00 91 fe 0c 0e 00 61 28 44 00 00 0a 9c fe 0c 0c 00 20 01 00 00 00 58 fe 0e 0c 00 fe 0c 0c 00 fe 09 00 00 8e 69 3f 43 ff ff ff } //0a 00 
		$a_01_1 = {fe 0c 06 00 fe 0c 03 00 fe 0c 05 00 94 58 fe 0c 04 00 fe 0c 05 00 94 58 28 68 00 00 06 28 43 00 00 0a 5d fe 0e 06 00 fe 0c 03 00 fe 0c 05 00 94 fe 0e 0b 00 fe 0c 03 00 fe 0c 05 00 fe 0c 03 00 fe 0c 06 00 94 9e fe 0c 03 00 fe 0c 06 00 fe 0c 0b 00 9e fe 0c 05 00 20 01 00 00 00 58 fe 0e 05 00 fe 0c 05 00 28 69 00 00 06 28 43 00 00 0a 3f 8c ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}