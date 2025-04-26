
rule PWS_BAT_Hawkeye_ACXK_MTB{
	meta:
		description = "PWS:BAT/Hawkeye.ACXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 02 8e b7 18 da 13 06 13 05 2b 65 02 11 05 91 0b 02 11 05 17 d6 91 0d 18 09 d8 03 da 07 da 13 04 03 07 da 09 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}