
rule Ransom_Win32_Genasom_N{
	meta:
		description = "Ransom:Win32/Genasom.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 63 74 69 76 61 74 65 2e 65 78 65 } //01 00 
		$a_01_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00 
		$a_01_2 = {8b 45 10 8b 48 04 49 83 e9 0b 72 05 83 38 08 75 09 83 38 1b 74 04 33 c0 eb 02 } //00 00 
	condition:
		any of ($a_*)
 
}