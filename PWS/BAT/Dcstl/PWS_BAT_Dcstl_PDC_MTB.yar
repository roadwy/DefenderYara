
rule PWS_BAT_Dcstl_PDC_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 26 07 28 90 01 03 0a 07 28 90 01 03 0a 0c 0d 16 13 90 00 } //02 00 
		$a_03_1 = {0a 26 08 7e 90 01 03 04 72 90 01 03 70 08 6f 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 26 07 17 58 0b 07 06 8e 69 32 bd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}