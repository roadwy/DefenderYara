
rule PWS_BAT_Dcstl_PDV_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 25 02 6f 90 01 03 06 00 0a 06 0b 07 28 90 01 03 0a 0c 72 90 01 03 70 08 28 90 01 03 0a 00 2a 90 00 } //01 00 
		$a_03_1 = {2e 17 58 13 2e 11 2b 73 90 01 03 06 13 30 11 30 11 2c 6f 90 01 03 06 26 72 90 01 03 70 12 2e 28 90 00 } //01 00 
		$a_03_2 = {13 0b 2b 27 11 0b 6f 90 01 03 0a 13 0c 00 00 11 0c 6f 90 01 03 0a 00 7e 90 01 03 04 28 90 01 03 0a 00 00 de 05 90 00 } //01 00 
		$a_03_3 = {13 1e 12 1e 28 90 01 03 0a a2 28 90 01 03 0a 28 90 01 03 0a 00 72 90 01 03 70 28 23 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}