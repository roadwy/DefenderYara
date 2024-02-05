
rule Trojan_Win32_Vundo_gen_Z{
	meta:
		description = "Trojan:Win32/Vundo.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 ff 35 30 00 00 00 58 c3 00 } //01 00 
		$a_03_1 = {66 81 38 4d 5a c3 00 90 09 05 00 e8 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_2 = {66 81 38 4d 5a 90 02 03 c3 00 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}