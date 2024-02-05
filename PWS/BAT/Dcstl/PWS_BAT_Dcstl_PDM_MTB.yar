
rule PWS_BAT_Dcstl_PDM_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {70 03 6f 13 90 01 02 0a 00 02 7b 90 01 03 04 02 28 90 01 03 06 7e 90 01 03 04 6f 90 01 03 0a 26 2a 90 00 } //01 00 
		$a_01_1 = {02 7b 01 00 00 04 6f 15 00 00 0a 00 2a } //01 00 
		$a_03_2 = {06 00 06 72 90 01 03 70 02 16 9a 72 90 01 03 70 28 90 01 03 0a 6f 90 01 03 06 00 00 de 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}