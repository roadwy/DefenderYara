
rule PWS_BAT_Dcstl_PDW_MTB{
	meta:
		description = "PWS:BAT/Dcstl.PDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 72 95 90 01 03 0b 28 90 01 03 06 72 90 01 03 70 28 90 01 03 0a 0c 73 16 90 00 } //1
		$a_03_1 = {0a 13 04 08 28 90 01 03 0a 13 05 11 04 11 05 16 11 05 8e 69 73 90 01 03 0a 72 90 01 03 70 06 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}