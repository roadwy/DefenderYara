
rule Backdoor_WinNT_Rustock_gen_C{
	meta:
		description = "Backdoor:WinNT/Rustock.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 24 6a 03 36 ff 75 08 } //01 00 
		$a_01_1 = {66 81 38 4d 5a } //02 00 
		$a_01_2 = {8b 45 ec 03 40 3c 8b 48 50 } //01 00 
		$a_01_3 = {0f b7 f8 66 81 e7 ff 0f 66 c1 e8 0c 83 f8 03 } //00 00 
	condition:
		any of ($a_*)
 
}