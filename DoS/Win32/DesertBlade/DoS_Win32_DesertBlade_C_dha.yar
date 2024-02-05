
rule DoS_Win32_DesertBlade_C_dha{
	meta:
		description = "DoS:Win32/DesertBlade.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 77 69 70 65 } //01 00 
		$a_01_1 = {e8 2b 57 fa ff 48 8b 44 24 20 48 8b 4c 24 28 48 } //01 00 
		$a_01_2 = {e8 a7 0a 00 00 48 8b 04 24 48 89 44 24 60 48 8b 4c } //00 00 
	condition:
		any of ($a_*)
 
}