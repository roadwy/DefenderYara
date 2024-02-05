
rule PWS_BAT_Hawkeye_ADIK_MTB{
	meta:
		description = "PWS:BAT/Hawkeye.ADIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 9a 0b 06 07 8e 69 6a 58 0a 11 06 17 58 13 06 11 06 11 05 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}