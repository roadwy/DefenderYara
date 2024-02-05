
rule PWS_BAT_CryptInjector_MTB{
	meta:
		description = "PWS:BAT/CryptInjector!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 01 00 00 06 0c 12 02 28 90 01 01 00 00 0a 74 90 01 01 00 00 1b 0d 16 13 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 12 04 28 02 00 00 06 26 11 04 2c 06 14 28 90 01 01 00 00 0a 72 01 00 00 70 09 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {26 7e 01 00 00 04 16 91 7e 01 00 00 04 17 91 1e 62 60 7e 01 00 00 04 18 91 1f 10 62 60 7e 01 00 00 04 19 91 1f 18 62 60 } //00 00 
	condition:
		any of ($a_*)
 
}