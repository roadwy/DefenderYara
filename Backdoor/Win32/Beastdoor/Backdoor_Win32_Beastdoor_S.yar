
rule Backdoor_Win32_Beastdoor_S{
	meta:
		description = "Backdoor:Win32/Beastdoor.S,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d7 8b 4d fc 02 54 19 ff 88 54 18 ff 43 4e 75 e7 } //01 00 
		$a_01_1 = {88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 f1 aa 66 05 bd 54 8b f0 43 66 ff 4c 24 04 75 } //01 00 
		$a_01_2 = {42 6f 6f 74 3a 20 5b 00 ff ff ff ff 03 00 00 00 5d 2d 5b 00 } //01 00 
		$a_01_3 = {7b 55 4e 44 4f 7d 00 00 ff ff ff ff 05 00 00 00 7b 54 41 42 7d 00 } //01 00 
		$a_01_4 = {41 49 4d 20 36 2e 78 00 ff ff ff ff 03 00 00 00 45 4e 44 00 } //01 00 
		$a_03_5 = {42 45 47 49 4e 20 43 4c 49 50 42 4f 41 52 44 90 02 0a 45 4e 44 20 43 4c 49 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}