
rule Worm_Win32_Narilam_A{
	meta:
		description = "Worm:Win32/Narilam.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 61 78 28 72 61 6a 29 20 66 72 6f 6d 20 48 6f 6c 69 64 61 79 5f 32 } //01 00 
		$a_01_1 = {6c 73 73 61 73 2e 65 78 65 00 6d 61 6c 69 72 61 6e 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}