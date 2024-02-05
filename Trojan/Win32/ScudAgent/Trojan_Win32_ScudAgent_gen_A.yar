
rule Trojan_Win32_ScudAgent_gen_A{
	meta:
		description = "Trojan:Win32/ScudAgent.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {7b 37 41 41 37 38 33 33 42 2d 31 32 33 31 2d 34 37 31 34 2d 41 53 44 41 2d 43 39 44 32 38 44 34 42 34 44 46 39 7d } //03 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 63 75 64 2e 70 69 70 69 73 2e 6e 65 74 2f } //03 00 
		$a_01_2 = {26 53 63 75 64 41 78 53 65 6e 64 4b 65 79 3d } //02 00 
		$a_01_3 = {4b 65 79 41 64 64 72 65 73 73 50 6f 70 55 70 } //00 00 
	condition:
		any of ($a_*)
 
}