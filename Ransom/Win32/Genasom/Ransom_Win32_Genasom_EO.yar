
rule Ransom_Win32_Genasom_EO{
	meta:
		description = "Ransom:Win32/Genasom.EO,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 04 00 00 64 00 "
		
	strings :
		$a_00_0 = {5c 77 69 6e 6c 6f 63 6b 2e 70 64 62 } //0a 00 
		$a_02_1 = {65 6e 74 65 72 90 03 04 00 20 74 68 65 20 63 6f 64 65 90 00 } //01 00 
		$a_00_2 = {2b 37 20 39 31 31 20 } //01 00 
		$a_00_3 = {2b 37 20 39 38 31 20 } //00 00 
	condition:
		any of ($a_*)
 
}