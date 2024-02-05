
rule Backdoor_Win32_Sdbot_AB{
	meta:
		description = "Backdoor:Win32/Sdbot.AB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 04 8d 90 01 01 d8 fd ff ff 90 01 01 6a 00 6a 00 68 90 01 02 40 00 6a 00 6a 00 ff 15 60 e0 40 00 50 ff 15 14 e0 40 00 90 00 } //01 00 
		$a_02_1 = {b8 01 00 00 00 85 c0 0f 84 90 01 02 00 00 8d 4d f0 51 8d 95 94 fc ff ff 52 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ec f9 40 00 6a 00 ff 15 40 e0 40 00 90 00 } //64 00 
		$a_01_2 = {25 64 00 00 32 36 30 30 00 00 00 00 44 4c 4c 00 44 4c 4c 00 53 79 73 74 65 6d 73 00 2a 00 00 00 25 64 00 00 32 36 30 30 } //00 00 
	condition:
		any of ($a_*)
 
}