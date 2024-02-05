
rule PWS_BAT_Lamikomio_A{
	meta:
		description = "PWS:BAT/Lamikomio.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2c 00 20 00 4c 00 65 00 76 00 65 00 6c 00 20 00 47 00 61 00 72 00 65 00 6e 00 61 00 20 00 3a 00 } //01 00 
		$a_00_1 = {54 00 68 00 61 00 6e 00 6b 00 20 00 59 00 6f 00 75 00 20 00 46 00 6f 00 72 00 20 00 55 00 73 00 65 00 21 00 20 00 23 00 } //06 00 
		$a_80_2 = {73 61 6e 74 69 61 67 6f 6d 75 6e 65 7a 66 69 66 61 40 67 6d 61 69 6c 2e 63 6f 6d } //santiagomunezfifa@gmail.com  00 00 
		$a_00_3 = {5d 04 00 00 4f 64 } //03 80 
	condition:
		any of ($a_*)
 
}