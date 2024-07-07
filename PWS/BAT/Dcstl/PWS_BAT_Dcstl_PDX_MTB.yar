
rule PWS_BAT_Dcstl_PDX_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 07 11 05 9a 6f 90 01 03 0a 2d 17 11 04 90 00 } //1
		$a_03_1 = {0a 0c 12 02 28 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 0c 12 02 90 00 } //1
		$a_03_2 = {2c 02 17 2a 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 2c 38 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}