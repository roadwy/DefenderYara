
rule Backdoor_Win32_Idicaf_gen_B{
	meta:
		description = "Backdoor:Win32/Idicaf.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 6a 90 01 01 5f 8d 0c 06 8b c6 99 f7 ff b0 90 01 01 2a c2 00 01 46 90 00 } //01 00 
		$a_00_1 = {70 6c 75 67 5f 6b 65 79 6c 6f 67 } //01 00  plug_keylog
		$a_03_2 = {5b 53 53 44 54 90 02 01 52 69 6e 67 30 90 02 04 3a 5d 20 25 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}