
rule Trojan_Win32_Kovter_J_{
	meta:
		description = "Trojan:Win32/Kovter.J!!Kovter.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {37 35 36 32 40 33 42 34 35 45 31 32 39 42 39 33 } //01 00 
		$a_00_1 = {40 6f 75 68 4b 6e 64 43 6e 79 } //01 00 
		$a_00_2 = {40 6f 75 68 40 6d 6d 45 64 63 74 66 66 64 73 72 } //01 00 
		$a_00_3 = {40 6f 75 68 53 47 51 } //00 00 
	condition:
		any of ($a_*)
 
}