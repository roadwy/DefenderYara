
rule Trojan_Win32_Tionas_C_dha{
	meta:
		description = "Trojan:Win32/Tionas.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {8a 0c 32 8a c2 04 90 01 01 8b fe 32 c8 33 c0 88 0c 32 83 c9 ff 42 90 00 } //01 00 
		$a_00_1 = {74 68 65 75 70 64 61 74 65 } //01 00 
		$a_00_2 = {75 70 64 61 74 65 72 2e 65 78 65 } //01 00 
		$a_00_3 = {69 63 74 33 32 2e 6d 73 6e 61 6d 65 2e 6f 72 67 } //00 00 
		$a_00_4 = {5d 04 00 } //00 c3 
	condition:
		any of ($a_*)
 
}