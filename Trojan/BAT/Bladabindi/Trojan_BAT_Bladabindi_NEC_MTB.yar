
rule Trojan_BAT_Bladabindi_NEC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1 } //01 00 
		$a_01_1 = {70 00 79 00 76 00 65 00 6c 00 72 00 55 00 2b 00 53 00 42 00 50 00 4d 00 2f 00 32 00 4d 00 57 00 45 00 66 00 74 00 69 00 65 00 41 00 3d 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}