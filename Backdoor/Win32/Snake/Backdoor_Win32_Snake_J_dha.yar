
rule Backdoor_Win32_Snake_J_dha{
	meta:
		description = "Backdoor:Win32/Snake.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 1c 07 30 1c 31 83 c0 01 3b c5 72 02 33 c0 83 c1 01 3b ca 72 ea } //01 00 
		$a_01_1 = {73 63 20 25 73 20 63 72 65 61 74 65 20 25 73 20 62 69 6e 50 61 74 68 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 25 25 53 79 73 74 65 6d 52 6f 6f 74 25 25 5c 25 73 22 3e 3e 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}