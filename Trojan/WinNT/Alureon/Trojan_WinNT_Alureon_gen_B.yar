
rule Trojan_WinNT_Alureon_gen_B{
	meta:
		description = "Trojan:WinNT/Alureon.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 46 50 89 47 10 8b 76 28 03 f3 57 ff d6 } //01 00 
		$a_02_1 = {68 1f 00 0f 00 8d 45 90 01 01 50 b8 90 01 04 ff d0 6a 01 6a 01 90 00 } //01 00 
		$a_02_2 = {50 68 00 00 00 80 8d 45 90 01 01 50 b8 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}