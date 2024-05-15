
rule Backdoor_Win32_Deppeels_A{
	meta:
		description = "Backdoor:Win32/Deppeels.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 6d 6f 74 65 20 63 6f 6d 70 75 74 65 72 20 77 69 6c 6c 20 62 65 65 6e 20 73 6c 65 65 70 70 65 64 20 66 6f 72 20 25 64 } //01 00  Remote computer will been sleepped for %d
		$a_01_1 = {66 75 63 6b 00 } //01 00 
		$a_01_2 = {49 6e 69 74 42 61 63 6b 44 6f 6f 72 28 29 } //01 00  InitBackDoor()
		$a_01_3 = {44 6c 6c 20 68 61 73 20 62 65 65 6e 20 64 65 6c 65 74 65 64 2c 72 65 63 6f 76 65 72 20 69 74 20 66 72 6f 6d 20 6d 65 6d 6f 72 79 21 } //01 00  Dll has been deleted,recover it from memory!
		$a_01_4 = {43 72 65 61 74 65 20 52 65 76 65 72 73 65 20 53 68 65 6c 6c 20 54 68 72 65 61 64 20 62 65 67 69 6e } //00 00  Create Reverse Shell Thread begin
		$a_01_5 = {00 67 } //16 00  最
	condition:
		any of ($a_*)
 
}