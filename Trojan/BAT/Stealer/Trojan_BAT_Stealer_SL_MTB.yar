
rule Trojan_BAT_Stealer_SL_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 03 06 13 00 38 00 00 00 00 dd e0 ff ff ff 26 38 00 00 00 00 dd d8 ff ff ff 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}