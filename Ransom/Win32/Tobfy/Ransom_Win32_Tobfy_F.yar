
rule Ransom_Win32_Tobfy_F{
	meta:
		description = "Ransom:Win32/Tobfy.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 73 6e 61 70 7a 2e 64 69 62 00 } //01 00 
		$a_01_1 = {2f 67 65 74 2e 70 68 70 00 } //01 00 
		$a_03_2 = {6a 03 56 56 6a 50 8b f8 68 90 01 04 57 ff 15 90 01 04 56 68 00 00 00 04 56 56 56 68 90 01 04 68 90 01 04 50 89 45 90 01 01 ff 15 90 01 04 ff 75 08 be 90 01 04 ff 75 90 01 01 89 45 90 01 01 56 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}