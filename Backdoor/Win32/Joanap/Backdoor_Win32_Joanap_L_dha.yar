
rule Backdoor_Win32_Joanap_L_dha{
	meta:
		description = "Backdoor:Win32/Joanap.L!dha,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 00 00 2e c6 84 24 ?? ?? 00 00 6d c6 84 24 ?? ?? 00 00 75 c6 84 24 ?? ?? 00 00 69 c6 84 24 ?? ?? 00 00 00 ff 15 } //10
		$a_03_1 = {48 8b d0 41 b9 04 00 00 00 48 03 cd 41 b8 00 10 00 00 ff 15 [0-34] 49 8b 04 24 ff c6 48 83 c7 28 0f b7 48 06 3b f1 } //10
		$a_03_2 = {b8 4d 5a 00 00 49 8b d9 4d 8b e8 4c 8b f2 4c 8b e1 66 39 01 74 ?? b9 c1 00 00 00 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=30
 
}