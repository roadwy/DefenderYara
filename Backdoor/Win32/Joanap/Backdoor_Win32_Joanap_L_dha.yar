
rule Backdoor_Win32_Joanap_L_dha{
	meta:
		description = "Backdoor:Win32/Joanap.L!dha,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 00 00 2e c6 84 24 90 01 02 00 00 6d c6 84 24 90 01 02 00 00 75 c6 84 24 90 01 02 00 00 69 c6 84 24 90 01 02 00 00 00 ff 15 90 00 } //0a 00 
		$a_03_1 = {48 8b d0 41 b9 04 00 00 00 48 03 cd 41 b8 00 10 00 00 ff 15 90 02 34 49 8b 04 24 ff c6 48 83 c7 28 0f b7 48 06 3b f1 90 00 } //0a 00 
		$a_03_2 = {b8 4d 5a 00 00 49 8b d9 4d 8b e8 4c 8b f2 4c 8b e1 66 39 01 74 90 01 01 b9 c1 00 00 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}