
rule Worm_BAT_Autorun_S{
	meta:
		description = "Worm:BAT/Autorun.S,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 90 02 05 6f 00 70 00 65 00 6e 00 3d 00 90 00 } //01 00 
		$a_00_1 = {48 74 74 70 46 6c 6f 6f 64 } //01 00  HttpFlood
		$a_00_2 = {55 44 50 46 6c 6f 6f 64 } //01 00  UDPFlood
		$a_00_3 = {77 00 69 00 64 00 74 00 68 00 3d 00 27 00 31 00 27 00 20 00 68 00 65 00 69 00 67 00 68 00 74 00 3d 00 27 00 31 00 27 00 } //01 00  width='1' height='1'
		$a_00_4 = {56 00 69 00 63 00 74 00 69 00 6d 00 20 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 21 00 } //00 00  Victim Connected!
	condition:
		any of ($a_*)
 
}