
rule Ransom_Win32_Basta_SI_MTB{
	meta:
		description = "Ransom:Win32/Basta.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d e0 8d 76 90 01 01 b8 90 01 04 f7 ef 03 d7 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 6b c0 90 01 01 2b c8 8b 45 90 01 01 8a 8c 39 90 01 04 32 8f 90 01 04 47 88 4c 06 90 01 01 3b 7d 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}