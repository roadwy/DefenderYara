
rule PWS_BAT_VB_B{
	meta:
		description = "PWS:BAT/VB.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {67 65 74 4d 53 4e 37 35 50 61 73 73 77 6f 72 64 73 } //01 00 
		$a_01_1 = {6b 69 6c 6c 70 72 6f 63 } //01 00 
		$a_01_2 = {66 69 6c 65 7a 69 6c 6c 61 } //02 00 
		$a_01_3 = {41 6e 74 69 53 61 6e 64 62 6f 78 } //00 00 
	condition:
		any of ($a_*)
 
}