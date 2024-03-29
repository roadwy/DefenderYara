
rule PWS_BAT_Stimilina_E{
	meta:
		description = "PWS:BAT/Stimilina.E,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 } //01 00  \config\
		$a_00_1 = {2a 00 2e 00 76 00 64 00 66 00 } //02 00  *.vdf
		$a_00_2 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 7b 00 30 00 7d 00 } //02 00  ftp://{0}
		$a_00_3 = {73 00 73 00 66 00 6e 00 2a 00 } //05 00  ssfn*
		$a_03_4 = {8d 07 00 00 01 13 06 11 06 16 1f 2f 9d 11 06 6f 06 00 00 0a 0c 72 90 01 02 00 70 03 28 07 00 00 0a 0d 08 13 07 16 13 08 90 00 } //00 00 
		$a_00_5 = {5d 04 00 00 06 39 } //03 80 
	condition:
		any of ($a_*)
 
}