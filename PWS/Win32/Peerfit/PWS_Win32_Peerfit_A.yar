
rule PWS_Win32_Peerfit_A{
	meta:
		description = "PWS:Win32/Peerfit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 ff 4d e4 0f 85 22 ff ff ff 8d 45 e8 e8 90 01 04 8b 46 08 8b 40 08 48 90 00 } //01 00 
		$a_01_1 = {6c 6f 67 20 69 6e 20 74 6f 20 79 6f 75 72 20 47 6d 61 69 6c } //01 00 
		$a_01_2 = {42 34 45 38 44 31 36 43 32 36 33 32 33 44 34 41 } //00 00 
	condition:
		any of ($a_*)
 
}