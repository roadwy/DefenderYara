
rule Trojan_Win32_Miuref_gen_A{
	meta:
		description = "Trojan:Win32/Miuref.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 46 54 03 41 3c 57 e8 90 01 04 8b 4d 08 8b 41 3c 03 c7 90 00 } //01 00 
		$a_03_1 = {8b 06 8b 48 28 85 c9 74 90 01 01 8b 46 04 03 c1 74 90 01 01 6a ff 6a 01 6a 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}