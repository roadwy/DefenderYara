
rule Trojan_Win32_Vundo_gen_BQ{
	meta:
		description = "Trojan:Win32/Vundo.gen!BQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {8b d4 cd 2e 89 90 03 01 01 45 85 90 00 } //01 00 
		$a_01_1 = {43 50 4d 2e 64 6c 6c 00 61 00 73 00 } //01 00 
		$a_01_2 = {41 56 55 4b 2e 64 6c 6c 00 64 00 } //01 00 
		$a_01_3 = {32 32 32 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 61 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}