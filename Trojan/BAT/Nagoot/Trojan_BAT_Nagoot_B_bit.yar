
rule Trojan_BAT_Nagoot_B_bit{
	meta:
		description = "Trojan:BAT/Nagoot.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 64 00 6c 64 00 6d 64 00 67 65 74 5f 62 00 67 65 74 5f 63 00 6e 64 00 6f 64 00 70 64 00 71 64 } //01 00 
		$a_03_1 = {73 65 74 5f 62 00 74 64 5f 30 00 77 64 00 78 64 90 02 40 6b 63 2e 72 65 73 6f 75 72 63 65 73 90 00 } //01 00 
		$a_01_2 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 } //01 00 
		$a_01_3 = {02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58 } //00 00 
	condition:
		any of ($a_*)
 
}