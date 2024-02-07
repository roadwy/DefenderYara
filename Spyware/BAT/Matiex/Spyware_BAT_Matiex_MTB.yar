
rule Spyware_BAT_Matiex_MTB{
	meta:
		description = "Spyware:BAT/Matiex!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2d 4d 2d 41 2d 54 2d 49 2d 45 2d 58 2d 2d 4b 2d 45 2d 59 2d 4c 2d 4f 2d 47 2d 45 2d 52 2d 2d } //01 00  --M-A-T-I-E-X--K-E-Y-L-O-G-E-R--
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {4d 79 43 6f 6d 70 75 74 65 72 } //00 00  MyComputer
	condition:
		any of ($a_*)
 
}