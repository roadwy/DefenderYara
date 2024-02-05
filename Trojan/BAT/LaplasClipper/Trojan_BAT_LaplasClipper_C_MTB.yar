
rule Trojan_BAT_LaplasClipper_C_MTB{
	meta:
		description = "Trojan:BAT/LaplasClipper.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 ff a2 3f 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 b8 00 00 00 28 00 00 00 59 00 00 00 de 01 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}