
rule Ransom_Win32_Dopplepaymer_gen_A{
	meta:
		description = "Ransom:Win32/Dopplepaymer.gen!A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {7e 00 31 00 3a 00 } //00 00  ~1:
	condition:
		any of ($a_*)
 
}