
rule Trojan_WinNT_Eqtonex_C{
	meta:
		description = "Trojan:WinNT/Eqtonex.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ee ff c0 d0 } //01 00 
		$a_01_1 = {ef be 00 d0 } //01 00 
		$a_01_2 = {6e 74 65 76 74 2e 73 79 73 } //01 00  ntevt.sys
		$a_01_3 = {5c 3f 3f 5c 43 3a } //00 00  \??\C:
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}