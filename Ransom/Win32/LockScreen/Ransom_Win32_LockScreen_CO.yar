
rule Ransom_Win32_LockScreen_CO{
	meta:
		description = "Ransom:Win32/LockScreen.CO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 06 6a 01 6a 02 ff 15 90 01 04 83 f8 ff 0f 84 90 01 02 00 00 a3 90 01 04 ba 90 01 04 8b 4c 24 08 89 4a 04 c7 02 02 00 00 50 6a 10 90 00 } //01 00 
		$a_03_1 = {6a 02 ff 15 90 01 04 33 f6 46 3b 35 90 01 04 90 03 04 06 74 90 01 01 0f 84 90 01 04 8b 3c b5 90 01 04 81 3f 68 74 74 70 75 03 83 c7 07 6a 2f 57 ff 15 90 01 04 0b c0 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}