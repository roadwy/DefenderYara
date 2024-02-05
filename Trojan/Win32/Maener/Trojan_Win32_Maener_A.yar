
rule Trojan_Win32_Maener_A{
	meta:
		description = "Trojan:Win32/Maener.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 65 72 5f 65 78 65 5f 6e 61 6d 65 } //01 00 
		$a_01_1 = {6d 69 6e 69 6e 67 5f 69 6e 66 6f } //03 00 
		$a_01_2 = {74 6f 6f 6c 73 2f 52 65 67 57 72 69 74 65 72 2e 65 78 65 } //05 00 
		$a_01_3 = {53 61 6d 61 65 6c 4c 6f 76 65 73 4d 65 } //05 00 
		$a_01_4 = {8b c3 c1 e8 10 88 06 8b c3 c1 e8 08 88 46 01 88 5e 02 83 c6 03 bb 01 00 00 00 } //05 00 
		$a_03_5 = {68 74 74 70 3a 2f 2f 31 2e 90 02 10 2e 7a 38 2e 72 75 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}