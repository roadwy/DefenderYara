
rule Backdoor_Win32_Pavica_B_dll{
	meta:
		description = "Backdoor:Win32/Pavica.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 0f b6 07 50 e8 06 00 00 00 25 32 2e 32 78 00 56 ff 15 90 01 04 83 c4 0c 47 83 c6 02 59 41 83 f9 10 75 db 90 00 } //01 00 
		$a_03_1 = {ff 75 0c e8 0c 00 00 00 73 7a 61 64 6d 69 6e 68 6f 73 74 00 ff 75 08 e8 90 01 04 85 c0 74 90 02 15 e8 08 00 00 00 68 74 74 70 3a 2f 2f 00 e8 90 00 } //02 00 
		$a_03_2 = {b9 02 00 00 00 58 5a 6a 00 52 50 e8 90 01 02 ff ff e2 f3 eb c3 90 09 29 00 83 3d 90 01 03 00 01 0f 84 90 01 02 ff ff e8 90 01 01 fe ff ff 68 90 01 02 00 07 81 2c 24 90 01 02 00 07 68 90 01 02 00 07 52 68 90 01 02 00 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}