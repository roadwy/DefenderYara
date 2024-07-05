
rule Ransom_Win64_Ransomhub_C_ldr{
	meta:
		description = "Ransom:Win64/Ransomhub.C!ldr,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 69 00 00 90 01 01 00 00 42 00 49 00 4e 00 00 00 2d 70 61 73 73 00 00 00 70 61 73 73 3a 0a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}