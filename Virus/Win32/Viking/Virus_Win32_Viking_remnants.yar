
rule Virus_Win32_Viking_remnants{
	meta:
		description = "Virus:Win32/Viking!remnants,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 5b 81 eb 05 02 40 00 64 8b 3d 30 00 00 00 8b 7f 0c 8b 7f 1c 8b 3f 8b 7f 08 89 bb } //01 00 
		$a_01_1 = {6a 00 51 83 c1 0a 8b 11 52 51 ba 4d 5a 90 00 89 11 56 ff d0 } //01 00 
		$a_01_2 = {52 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 83 c2 44 52 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}