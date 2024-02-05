
rule Ransom_Win64_Ryuk_PD_MTB{
	meta:
		description = "Ransom:Win64/Ryuk.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {41 8b c9 41 f7 e9 90 02 03 41 ff c1 c1 fa 90 01 01 8b c2 c1 e8 1f 03 d0 69 c2 90 01 02 00 00 2b c8 48 63 c1 8a 84 30 90 01 03 00 41 30 02 49 ff c2 41 81 f9 90 01 02 00 00 7c 90 00 } //01 00 
		$a_02_1 = {41 f6 c2 01 75 06 41 8a 04 29 eb 90 01 01 41 8b c3 41 8b ca 41 f7 ea 90 02 03 c1 fa 90 01 01 8b c2 c1 e8 1f 03 d0 6b c2 90 01 01 2b c8 48 63 c1 8a 84 30 90 01 03 00 41 30 84 31 90 01 03 00 41 ff c2 49 ff c1 41 83 fa 90 01 01 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}