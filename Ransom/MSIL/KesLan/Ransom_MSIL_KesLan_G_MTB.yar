
rule Ransom_MSIL_KesLan_G_MTB{
	meta:
		description = "Ransom:MSIL/KesLan.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {13 04 09 11 04 09 6f 90 01 04 1e 5b 6f 90 01 09 00 09 11 04 09 6f 90 01 04 1e 5b 6f 90 01 09 00 09 17 6f 90 01 04 00 08 09 6f 90 01 04 17 73 90 01 04 13 05 90 00 } //01 00 
		$a_80_1 = {42 54 43 28 42 69 74 63 6f 69 6e 29 20 41 64 64 72 65 73 73 3a } //BTC(Bitcoin) Address:  01 00 
		$a_80_2 = {42 65 6e 3a 20 20 4b 65 73 20 4c 61 6e } //Ben:  Kes Lan  00 00 
	condition:
		any of ($a_*)
 
}