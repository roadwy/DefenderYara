
rule Backdoor_Win32_Toghoob_A{
	meta:
		description = "Backdoor:Win32/Toghoob.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {39 45 f8 73 1b 8b 45 08 03 45 fc 8b 4d f8 8a 00 32 81 90 01 04 8b 4d 08 03 4d fc 88 01 eb ce 90 00 } //01 00 
		$a_03_1 = {6a 11 6a 02 6a 02 ff 15 90 01 04 89 85 54 fc ff ff 83 bd 54 fc ff ff ff 75 07 33 c0 e9 51 01 00 00 90 00 } //01 00 
		$a_01_2 = {8b 44 81 fc 0f be 00 83 f8 23 74 31 6a 21 } //00 00 
	condition:
		any of ($a_*)
 
}