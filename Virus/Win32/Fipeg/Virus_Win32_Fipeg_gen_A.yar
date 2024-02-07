
rule Virus_Win32_Fipeg_gen_A{
	meta:
		description = "Virus:Win32/Fipeg.gen!A,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 73 79 73 74 65 6d 7e 2e 69 6e 69 } //01 00  _system~.ini
		$a_01_1 = {25 73 5c 64 72 69 76 65 72 73 } //01 00  %s\drivers
		$a_01_2 = {25 73 5c 25 73 } //01 00  %s\%s
		$a_01_3 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 } //01 00  %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c
		$a_01_4 = {2e 7e 74 6d 70 } //01 00  .~tmp
		$a_01_5 = {25 73 5c 64 72 69 76 65 72 73 5c 25 73 } //01 00  %s\drivers\%s
		$a_01_6 = {63 6d 64 2e 70 69 66 } //01 00  cmd.pif
		$a_01_7 = {4d 43 49 20 50 72 6f 67 72 61 6d 20 43 6f 6d 20 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00  MCI Program Com Application
		$a_01_8 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 70 61 67 65 2e 70 69 66 } //00 00  shellexecute=page.pif
	condition:
		any of ($a_*)
 
}