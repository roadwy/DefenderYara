
rule Trojan_BAT_SnakeKeyLogger_RDBB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 75 6b 63 69 6f 6e 44 42 44 61 74 61 53 65 74 } //1 AukcionDBDataSet
		$a_01_1 = {44 42 69 64 6f 6e 74 77 61 6e 74 67 6f 74 6f 74 68 65 61 72 6d 79 } //1 DBidontwantgotothearmy
		$a_01_2 = {46 6f 72 6d 41 64 64 41 75 6b 63 69 6f 6e } //1 FormAddAukcion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}