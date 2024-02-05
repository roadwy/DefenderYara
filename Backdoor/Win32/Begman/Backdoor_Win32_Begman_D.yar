
rule Backdoor_Win32_Begman_D{
	meta:
		description = "Backdoor:Win32/Begman.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b f2 8a 10 8b d9 c1 eb 08 32 da 88 18 81 e2 ff 00 00 00 03 ca 0f af 4d 08 40 4e 85 f6 75 e3 5e } //01 00 
		$a_01_1 = {50 68 34 4d 40 00 68 a4 43 40 00 e8 5f db ff ff a1 a0 53 40 00 50 a1 9c 53 40 00 50 68 ac 42 40 00 68 c0 3b 40 00 e8 44 db ff ff e8 83 08 00 00 } //01 00 
		$a_03_2 = {56 42 4f 58 90 02 0f 51 45 4d 55 90 02 0a 55 8b ec 6a 00 6a 00 53 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}