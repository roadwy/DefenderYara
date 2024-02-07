
rule PWS_BAT_Dcstl_ABR_MTB{
	meta:
		description = "PWS:BAT/Dcstl.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 16 73 92 90 01 02 0a 0c 73 90 01 03 0a 0d 08 09 28 1e 90 01 02 06 09 16 6a 6f 90 01 03 0a 09 13 04 de 1c 08 2c 06 08 6f 90 01 03 0a dc 90 00 } //02 00 
		$a_01_1 = {02 6f 96 00 00 0a d4 8d 63 00 00 01 0a 02 06 16 06 8e 69 6f 8e 00 00 0a 26 06 2a } //01 00 
		$a_01_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00  GetManifestResourceStream
		$a_01_3 = {44 00 42 00 54 00 65 00 73 00 74 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  DBTest.Properties.Resources
	condition:
		any of ($a_*)
 
}