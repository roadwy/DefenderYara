
rule Trojan_Win32_Farfli_AK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 ab 3b 5e ad 43 8e 19 89 e8 1b be 88 12 80 e7 12 e3 ee 7b eb } //01 00 
		$a_01_1 = {25 73 2e 65 78 65 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}