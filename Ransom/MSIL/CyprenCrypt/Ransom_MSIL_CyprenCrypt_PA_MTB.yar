
rule Ransom_MSIL_CyprenCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/CyprenCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 76 00 69 00 6e 00 67 00 67 00 50 00 6f 00 72 00 6e 00 } //01 00  LovinggPorn
		$a_01_1 = {5c 00 52 00 45 00 43 00 55 00 50 00 45 00 52 00 41 00 52 00 5f 00 5f 00 2e 00 70 00 6f 00 72 00 6e 00 2e 00 74 00 78 00 74 00 } //01 00  \RECUPERAR__.porn.txt
		$a_01_2 = {2e 00 70 00 6f 00 72 00 6e 00 } //01 00  .porn
		$a_01_3 = {66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  files have been encrypted
	condition:
		any of ($a_*)
 
}