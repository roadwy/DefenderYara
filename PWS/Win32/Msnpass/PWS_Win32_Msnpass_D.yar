
rule PWS_Win32_Msnpass_D{
	meta:
		description = "PWS:Win32/Msnpass.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {38 30 30 34 38 38 32 33 90 09 0f 00 43 6f 64 65 20 64 65 72 72 65 75 72 20 3a 20 90 00 } //01 00 
		$a_03_1 = {48 61 71 6d 73 6e 2e 61 73 70 3f 70 63 3d 90 09 16 00 75 73 65 72 33 2e 6a 61 62 72 79 2e 63 6f 6d 2f 70 72 6f 32 33 2f 90 00 } //01 00 
		$a_03_2 = {26 70 6d 61 69 6c 3d 90 01 09 26 70 77 3d 90 01 0c 26 6d 61 69 6c 3d 90 01 0a 26 63 6f 75 6e 74 72 79 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}