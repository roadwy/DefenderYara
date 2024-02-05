
rule Backdoor_Win32_Afcore_gen_H{
	meta:
		description = "Backdoor:Win32/Afcore.gen!H,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 75 74 65 78 5f 77 69 6e 69 6e 69 74 2e 69 6e 69 00 } //01 00 
		$a_01_1 = {83 7d 08 00 75 08 b8 4e 55 4c 3d ab eb 1f } //01 00 
		$a_01_2 = {33 d2 f7 f1 80 c2 61 88 17 } //00 00 
	condition:
		any of ($a_*)
 
}