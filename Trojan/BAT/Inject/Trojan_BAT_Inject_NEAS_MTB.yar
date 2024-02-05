
rule Trojan_BAT_Inject_NEAS_MTB{
	meta:
		description = "Trojan:BAT/Inject.NEAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {00 00 0a 06 8e 69 20 00 30 00 00 1f 40 28 90 01 01 00 00 06 13 04 09 11 04 06 06 8e 69 12 01 28 90 01 01 00 00 06 13 05 11 05 13 07 11 07 2c 2d 00 20 fb 03 00 00 16 08 90 00 } //05 00 
		$a_01_1 = {41 00 50 00 43 00 49 00 6e 00 6a 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}