
rule Trojan_WinNT_Tandfuy_B{
	meta:
		description = "Trojan:WinNT/Tandfuy.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 41 00 68 00 6e 00 46 00 6c 00 74 00 32 00 4b 00 2e 00 73 00 79 00 73 00 00 00 } //01 00 
		$a_03_1 = {c6 06 4d c6 46 01 5a c6 46 02 90 90 88 5e 03 c6 46 04 03 88 5e 05 88 5e 06 88 5e 07 c6 46 08 04 88 5e 09 ff 15 90 01 04 53 53 6a 20 6a 03 6a 02 6a 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}