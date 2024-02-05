
rule Trojan_Win32_Canahom_gen_A{
	meta:
		description = "Trojan:Win32/Canahom.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2b cf 42 66 ad 8b f7 33 c2 66 3d 43 3a 75 f3 ac 32 c2 aa 42 e2 f9 c3 } //01 00 
		$a_02_1 = {66 81 3e 43 3a 74 19 50 50 e8 90 01 01 00 00 00 50 5a 8b fe 8d 0d 90 01 04 2b ce ac 32 c2 aa e2 fa 61 c3 90 00 } //01 00 
		$a_02_2 = {75 03 89 45 f4 83 7d f4 00 74 16 6a 00 56 e8 90 01 02 ff ff 8b 06 3d 77 61 69 74 74 05 33 c0 89 45 f4 90 00 } //01 00 
		$a_02_3 = {eb 62 81 3e 2d 6d 64 35 75 59 81 7e 01 6d 64 35 5b 75 50 83 eb 05 83 c6 05 8d 85 90 01 02 ff ff 50 6a 01 6a 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}