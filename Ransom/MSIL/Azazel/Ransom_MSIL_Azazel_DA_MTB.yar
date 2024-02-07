
rule Ransom_MSIL_Azazel_DA_MTB{
	meta:
		description = "Ransom:MSIL/Azazel.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 7a 61 7a 65 6c 20 69 73 20 74 68 65 20 62 65 73 74 20 6f 6f 20 79 65 61 68 20 62 69 74 63 68 } //01 00  azazel is the best oo yeah bitch
		$a_81_1 = {2e 61 7a 61 7a 65 6c } //01 00  .azazel
		$a_81_2 = {6b 6b 2e 65 78 65 } //00 00  kk.exe
	condition:
		any of ($a_*)
 
}