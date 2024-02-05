
rule Backdoor_Win32_Briba_A{
	meta:
		description = "Backdoor:Win32/Briba.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 67 69 6e 6d 69 64 3d 25 73 26 6e 69 63 6b 69 64 3d 30 26 73 3d 25 73 } //01 00 
		$a_01_1 = {63 30 64 30 73 6f 30 } //01 00 
		$a_01_2 = {80 3e 47 75 0c 80 7e 01 49 75 06 80 7e 02 46 74 07 } //00 00 
	condition:
		any of ($a_*)
 
}