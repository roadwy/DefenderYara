
rule PWS_BAT_Dcstl_PDF_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 25 0a 0b 72 90 01 03 70 0c 72 90 01 03 70 72 90 01 03 70 73 90 01 03 0a 28 90 01 03 0a 0d 73 90 01 03 0a 13 04 90 00 } //01 00 
		$a_03_1 = {13 05 07 28 90 01 03 0a 13 06 11 05 28 90 01 03 0a 09 6f 90 01 03 0a 16 28 90 01 03 0a 09 6f 90 01 03 0a 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}