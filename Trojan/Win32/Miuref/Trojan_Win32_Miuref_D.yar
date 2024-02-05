
rule Trojan_Win32_Miuref_D{
	meta:
		description = "Trojan:Win32/Miuref.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 06 8b 48 28 85 c9 74 1a 8b 46 04 03 c1 74 13 6a ff 6a 01 6a 00 ff d0 85 c0 } //01 00 
		$a_01_1 = {c7 40 44 02 00 00 00 c7 40 48 4d dd eb 5a c7 40 4c a1 ce eb 5a } //00 00 
	condition:
		any of ($a_*)
 
}