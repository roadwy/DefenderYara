
rule Backdoor_BAT_Pontoeb_B{
	meta:
		description = "Backdoor:BAT/Pontoeb.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 42 6f 74 00 75 70 64 61 74 65 42 6f 74 00 52 65 6d 6f 76 65 42 6f 74 00 } //01 00 
		$a_00_1 = {26 00 62 00 6f 00 74 00 76 00 65 00 72 00 3d 00 } //01 00  &botver=
		$a_00_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 42 00 61 00 73 00 65 00 42 00 6f 00 61 00 72 00 64 00 } //00 00  SELECT * FROM Win32_BaseBoard
	condition:
		any of ($a_*)
 
}