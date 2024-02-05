
rule Ransom_Win32_Basta_AD_MTB{
	meta:
		description = "Ransom:Win32/Basta.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 39 74 24 90 01 01 76 90 01 01 b8 90 01 04 8b ce f7 ee c1 fa 03 8b c2 c1 e8 1f 03 c2 6b c0 90 01 01 2b c8 8b 44 24 90 01 01 8a 89 90 01 04 32 8e 90 01 04 88 0c 06 46 3b 74 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}