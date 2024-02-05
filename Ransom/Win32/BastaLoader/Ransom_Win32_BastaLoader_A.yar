
rule Ransom_Win32_BastaLoader_A{
	meta:
		description = "Ransom:Win32/BastaLoader.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_1 = {5f 00 63 00 2e 00 64 00 6c 00 6c 00 2c 00 76 00 69 00 73 00 69 00 62 00 6c 00 65 00 65 00 6e 00 74 00 72 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}