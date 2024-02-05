
rule Backdoor_WinNT_Tofsee_D{
	meta:
		description = "Backdoor:WinNT/Tofsee.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 c9 39 4c 24 08 76 0f 8b 44 24 04 03 c1 f6 10 41 3b 4c 24 08 72 f1 } //02 00 
		$a_01_1 = {68 5f 4e 54 4c ff 74 24 08 ff 15 } //02 00 
		$a_01_2 = {8b 0f 8b 41 3c 8d 44 08 04 0f b7 50 02 0f b7 40 10 89 55 f8 6b d2 28 } //01 00 
		$a_01_3 = {5c 00 72 00 6f 00 74 00 63 00 65 00 74 00 6f 00 72 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}