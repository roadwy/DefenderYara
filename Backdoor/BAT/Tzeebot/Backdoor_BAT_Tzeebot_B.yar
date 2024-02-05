
rule Backdoor_BAT_Tzeebot_B{
	meta:
		description = "Backdoor:BAT/Tzeebot.B,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 46 69 6c 65 4d 44 35 43 6f 6d 70 6c 65 74 65 64 } //01 00 
		$a_01_1 = {67 65 74 5f 48 61 69 66 61 } //05 00 
		$a_03_2 = {06 17 58 0a 90 0a 40 00 07 7e 90 01 02 00 04 7e 90 01 02 00 04 90 02 02 6f 90 01 02 00 0a 6f 90 01 02 00 0a 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 0b 90 00 } //0a 00 
		$a_01_3 = {54 69 6e 79 5a 42 6f 74 } //00 00 
		$a_00_4 = {5d 04 00 00 9c 27 03 80 5c 21 00 00 } //9d 27 
	condition:
		any of ($a_*)
 
}