
rule Trojan_Win32_Bodime_A{
	meta:
		description = "Trojan:Win32/Bodime.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 c7 44 24 90 01 01 d5 07 66 c7 44 24 90 01 01 08 00 66 c7 44 24 90 01 01 11 00 66 c7 44 24 90 01 01 14 00 90 00 } //01 00 
		$a_01_1 = {b9 00 00 04 00 b8 4b 4b 4b 4b } //01 00 
		$a_01_2 = {77 69 6e 6e 65 74 2e 69 6d 65 } //00 00  winnet.ime
	condition:
		any of ($a_*)
 
}