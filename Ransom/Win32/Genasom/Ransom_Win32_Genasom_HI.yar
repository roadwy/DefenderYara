
rule Ransom_Win32_Genasom_HI{
	meta:
		description = "Ransom:Win32/Genasom.HI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 68 65 31 30 32 34 72 73 61 40 69 32 70 6d 61 69 6c 2e 6f 72 67 } //01 00 
		$a_01_1 = {28 70 68 6f 74 6f 73 2c 64 6f 63 75 6d 65 6e 74 73 20 65 74 63 2e 29 } //01 00 
		$a_01_2 = {48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 2e 74 78 74 20 } //02 00 
		$a_01_3 = {51 57 0f 31 5f 59 25 f0 00 00 00 c1 e8 04 83 c0 61 aa e2 ec } //02 00 
		$a_01_4 = {b9 19 00 00 00 bb 01 00 00 00 d3 e3 23 d8 74 1f 80 c1 41 } //00 00 
	condition:
		any of ($a_*)
 
}