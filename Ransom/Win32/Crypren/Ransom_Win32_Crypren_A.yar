
rule Ransom_Win32_Crypren_A{
	meta:
		description = "Ransom:Win32/Crypren.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 63 72 79 70 74 65 64 5f 70 6f 6e 79 5f 74 65 73 74 5f 62 75 69 6c 64 5f 78 78 78 5f 78 78 78 5f 78 78 78 5f 78 78 78 5f 78 78 78 } //01 00 
		$a_01_1 = {70 6f 6e 79 20 6c 6f 76 65 20 79 6f 75 } //01 00 
		$a_00_2 = {2a 2e 62 61 74 0d 0a 2a 2e 62 66 63 0d 0a 2a 2e 62 67 0d 0a 2a 2e 62 69 6e 0d 0a 2a 2e 62 6b 32 0d 0a 2a 2e 62 6d 70 0d 0a 2a 2e 62 6e 6b } //00 00 
	condition:
		any of ($a_*)
 
}