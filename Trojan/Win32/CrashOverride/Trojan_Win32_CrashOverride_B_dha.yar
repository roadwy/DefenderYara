
rule Trojan_Win32_CrashOverride_B_dha{
	meta:
		description = "Trojan:Win32/CrashOverride.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {e0 07 0c 00 90 02 03 c7 90 01 03 11 00 16 00 c7 90 01 03 1b 00 00 00 90 00 } //05 00 
		$a_00_1 = {8b 44 24 1c 89 44 24 44 8b 44 24 18 89 44 24 40 8d 44 24 3c } //05 00 
		$a_80_2 = {68 61 73 6c 6f 2e 64 61 74 } //haslo.dat  00 00 
		$a_00_3 = {5d 04 00 00 50 } //b3 03 
	condition:
		any of ($a_*)
 
}