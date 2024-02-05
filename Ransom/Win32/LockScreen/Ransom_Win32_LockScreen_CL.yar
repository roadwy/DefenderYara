
rule Ransom_Win32_LockScreen_CL{
	meta:
		description = "Ransom:Win32/LockScreen.CL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 00 } //01 00 
		$a_03_1 = {8b 45 0c 8b 55 08 85 d2 75 23 3d 04 02 00 00 74 07 3d 05 02 00 00 75 15 3d 05 02 00 00 75 07 6a 01 e8 90 01 04 b8 02 00 00 00 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}