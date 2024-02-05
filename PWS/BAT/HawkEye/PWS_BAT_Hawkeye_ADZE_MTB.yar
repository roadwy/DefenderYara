
rule PWS_BAT_Hawkeye_ADZE_MTB{
	meta:
		description = "PWS:BAT/Hawkeye.ADZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 08 91 1f 1f 31 20 07 08 91 1f 7f 2f 19 07 08 13 04 11 04 07 11 04 91 08 1f 1f 5d 1f 10 d6 28 } //00 00 
	condition:
		any of ($a_*)
 
}