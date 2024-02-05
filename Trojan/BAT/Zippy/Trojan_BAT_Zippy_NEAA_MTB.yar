
rule Trojan_BAT_Zippy_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Zippy.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a de 0a 07 2c 06 07 6f 05 00 00 0a dc 28 06 00 00 0a 72 90 01 01 00 00 70 28 07 00 00 0a 06 28 08 00 00 0a 20 e8 03 00 00 28 09 00 00 0a 28 06 00 00 0a 72 90 01 01 00 00 70 28 07 00 00 0a 28 0a 00 00 0a 26 de 03 90 00 } //05 00 
		$a_01_1 = {69 00 74 00 73 00 65 00 6c 00 66 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}