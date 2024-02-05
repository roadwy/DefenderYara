
rule Trojan_Win32_AresLdr_LK_MTB{
	meta:
		description = "Trojan:Win32/AresLdr.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 72 65 73 4c 64 72 5f } //05 00 
		$a_03_1 = {68 74 74 70 3a 2f 2f 90 02 f0 2f 70 61 79 6c 6f 61 64 90 00 } //05 00 
		$a_03_2 = {68 74 74 70 3a 2f 2f 90 02 f0 2f 6c 65 67 69 74 90 00 } //01 00 
		$a_03_3 = {67 65 6f 5c 90 02 05 3a 20 27 25 73 27 2c 20 5c 90 02 05 73 65 72 76 69 63 65 5c 90 02 05 3a 20 27 25 73 27 2c 20 5c 90 02 05 6f 77 6e 65 72 5f 74 6f 6b 65 6e 90 00 } //01 00 
		$a_01_4 = {74 7a 75 74 69 6c 20 2f 67 } //00 00 
	condition:
		any of ($a_*)
 
}