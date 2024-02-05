
rule Ransom_Win64_Magniber_ZZ{
	meta:
		description = "Ransom:Win64/Magniber.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 ff 69 00 65 00 c7 45 03 78 00 70 00 c7 45 07 6c 00 6f 00 } //01 00 
		$a_01_1 = {c7 45 0f 2e 00 65 00 c7 45 13 78 00 65 00 66 44 89 65 17 c7 45 c7 6e 00 74 00 c7 45 cb 64 00 6c 00 c7 45 cf 6c 00 2e 00 c7 45 d3 64 00 6c 00 c7 45 d7 6c 00 00 00 c7 45 df 6b 00 65 00 c7 45 e3 72 00 6e 00 c7 45 e7 65 00 6c 00 c7 45 eb 33 00 32 00 c7 45 ef 2e 00 64 00 c7 45 f3 6c 00 6c 00 66 44 89 65 f7 } //01 00 
		$a_01_2 = {40 30 39 41 03 ff 81 ff ff 00 00 00 41 0f 44 ff 49 03 cf 49 2b d7 75 e8 } //00 00 
	condition:
		any of ($a_*)
 
}