
rule Trojan_Win32_Balisdat_gen_B{
	meta:
		description = "Trojan:Win32/Balisdat.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 66 7a 66 2e 90 02 10 5c 3a 64 90 00 } //01 00 
		$a_00_1 = {6f 76 53 5c 6f 70 6a 74 73 66 58 75 6f 66 73 73 76 44 } //01 00 
		$a_00_2 = {2f 2f 3a 71 75 75 69 } //00 00 
	condition:
		any of ($a_*)
 
}