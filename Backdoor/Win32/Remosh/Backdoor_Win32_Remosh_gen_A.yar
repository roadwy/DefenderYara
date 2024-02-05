
rule Backdoor_Win32_Remosh_gen_A{
	meta:
		description = "Backdoor:Win32/Remosh.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 33 f6 39 74 24 0c 7e 1a 8b 4c 24 08 57 8b c6 bf 90 01 01 00 00 00 99 f7 ff 30 11 41 46 3b 74 24 10 7c ec 5f 5e c3 90 00 } //01 00 
		$a_01_1 = {66 89 45 f0 8a 45 10 57 33 ff 84 c0 88 45 f2 88 4d fb c7 45 fc 68 57 24 13 74 3e } //01 00 
		$a_01_2 = {83 c4 10 84 c0 74 5c 81 7e 0c 68 57 24 13 75 53 8b 46 03 85 c0 0f 86 93 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}