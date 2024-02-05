
rule PWS_Win32_Donips_gen_A{
	meta:
		description = "PWS:Win32/Donips.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {be 52 41 57 00 8b c1 40 39 30 75 fb 8b f0 4a 75 f4 40 66 81 38 55 8b 75 f8 83 e8 05 } //03 00 
		$a_03_1 = {eb c3 68 24 01 00 00 ff 75 f8 68 dc a0 6c 6c ff 35 90 01 02 00 10 e8 90 01 02 ff ff 59 59 ff d0 89 45 fc 90 00 } //02 00 
		$a_03_2 = {7d 21 8b 55 08 03 55 fc 0f be 02 8b 0d 90 01 04 c1 f9 08 0f be d1 33 c2 8b 4d 08 03 4d fc 88 01 eb c7 90 00 } //01 00 
		$a_03_3 = {59 59 6a 00 68 90 09 45 00 90 03 03 00 90 01 0e 6a 00 6a 04 6a 02 6a 00 6a 00 68 00 00 00 c0 90 00 } //01 00 
		$a_09_4 = {5b 57 4d 49 44 5d 00 00 5b 57 4d 50 53 5d } //01 00 
		$a_09_5 = {6d 70 72 61 70 69 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}