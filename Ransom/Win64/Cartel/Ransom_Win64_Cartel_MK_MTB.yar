
rule Ransom_Win64_Cartel_MK_MTB{
	meta:
		description = "Ransom:Win64/Cartel.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 8b 90 01 06 48 23 90 01 03 48 8b c1 48 8b 90 01 06 48 8b 90 01 06 48 90 01 03 48 33 c8 48 8b c1 8b 8c 24 90 01 04 8b 94 24 90 01 04 03 d1 8b ca 48 63 c9 48 8b 94 24 90 01 04 48 89 90 01 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}