
rule Ransom_Win32_Basta_D_ldr{
	meta:
		description = "Ransom:Win32/Basta.D!ldr,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 68 6f 66 72 2e 44 90 01 01 4c 90 00 } //01 00 
		$a_03_1 = {66 67 31 32 32 2e 44 90 01 01 4c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}