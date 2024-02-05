
rule Trojan_BAT_LimeRAT_MAAJ_MTB{
	meta:
		description = "Trojan:BAT/LimeRAT.MAAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 37 65 35 36 32 62 63 31 2d 32 65 36 33 2d 34 61 32 35 2d 61 32 33 35 2d 65 39 31 39 66 36 63 39 65 30 33 62 } //01 00 
		$a_01_1 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}