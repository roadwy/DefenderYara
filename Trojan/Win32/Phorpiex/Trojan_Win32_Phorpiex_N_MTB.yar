
rule Trojan_Win32_Phorpiex_N_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 6f 00 73 00 74 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 66 00 6f 00 72 00 } //01 00  Host Process for
		$a_01_1 = {50 00 68 00 6f 00 72 00 70 00 69 00 65 00 78 00 } //01 00  Phorpiex
		$a_01_2 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 4d 00 61 00 6e 00 61 00 } //01 00  Desktop Window Mana
		$a_01_3 = {25 00 73 00 5c 00 72 00 33 00 33 00 72 00 33 00 72 00 33 00 72 00 2e 00 74 00 78 00 74 00 } //01 00  %s\r33r3r3r.txt
		$a_01_4 = {25 00 73 00 5c 00 77 00 33 00 74 00 33 00 74 00 77 00 66 00 2e 00 74 00 78 00 74 00 } //00 00  %s\w3t3twf.txt
	condition:
		any of ($a_*)
 
}