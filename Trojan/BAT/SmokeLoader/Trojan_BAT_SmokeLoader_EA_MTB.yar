
rule Trojan_BAT_SmokeLoader_EA_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {11 03 17 58 13 03 38 a3 ff ff ff 11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 03 11 03 91 61 d2 9c } //03 00 
		$a_01_1 = {4e 00 76 00 63 00 78 00 74 00 77 00 } //00 00  Nvcxtw
	condition:
		any of ($a_*)
 
}