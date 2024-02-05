
rule PWS_BAT_Dcstl_PDQ_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 0b 72 b7 90 01 03 72 90 01 03 70 02 7b 90 01 03 04 6f 90 01 03 0a 26 00 de 0d 11 0b 2c 08 11 0b 6f 90 01 03 0a 00 dc 90 00 } //01 00 
		$a_03_1 = {02 1f 1a 28 90 01 03 0a 7d 90 01 03 04 02 1f 28 28 90 01 03 0a 7d 90 01 03 04 02 73 90 01 03 0a 7d 90 01 03 04 02 28 90 01 03 0a 00 2a 90 00 } //01 00 
		$a_03_2 = {06 0a 06 72 90 01 03 70 6f 90 01 03 06 00 06 72 90 01 03 70 6f 90 01 03 06 00 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}