
rule Ransom_Win32_BlackCat_ABC_MTB{
	meta:
		description = "Ransom:Win32/BlackCat.ABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 f0 b9 59 17 b7 d1 f7 e1 89 f1 c1 ea 0d 69 c2 10 27 00 00 29 c1 0f b7 c1 c1 e8 02 69 c0 7b 14 00 00 c1 e8 11 6b f8 64 0f b7 84 00 e4 e3 60 00 29 f9 81 fe ff e0 f5 05 89 d6 } //00 00 
	condition:
		any of ($a_*)
 
}