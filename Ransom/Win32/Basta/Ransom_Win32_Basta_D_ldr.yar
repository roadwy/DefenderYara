
rule Ransom_Win32_Basta_D_ldr{
	meta:
		description = "Ransom:Win32/Basta.D!ldr,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {47 68 6f 66 72 2e 44 ?? 4c } //1
		$a_03_1 = {66 67 31 32 32 2e 44 ?? 4c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}