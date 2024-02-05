
rule Spammer_Win32_Cutwail_gen_D{
	meta:
		description = "Spammer:Win32/Cutwail.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {76 0d 8a 14 30 30 54 01 04 40 3b 41 90 01 01 72 f3 5e 90 00 } //01 00 
		$a_03_1 = {68 58 02 00 00 03 c6 50 ff 75 08 c7 45 90 01 01 78 56 34 12 90 00 } //01 00 
		$a_01_2 = {66 39 46 06 89 45 fc 76 57 8d be 08 01 00 00 8b 0f 85 c9 74 37 80 7d 0f 00 74 15 } //00 00 
	condition:
		any of ($a_*)
 
}