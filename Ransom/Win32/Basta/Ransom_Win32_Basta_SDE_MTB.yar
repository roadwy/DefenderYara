
rule Ransom_Win32_Basta_SDE_MTB{
	meta:
		description = "Ransom:Win32/Basta.SDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 02 e9 90 01 04 8b 00 e9 90 01 04 0f b7 4a 90 01 01 e9 90 01 04 8b d0 e9 90 01 04 32 02 e9 90 01 04 8b d8 e9 90 01 04 8d 73 90 01 01 e9 90 01 04 89 75 90 01 01 e9 90 01 04 f7 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}