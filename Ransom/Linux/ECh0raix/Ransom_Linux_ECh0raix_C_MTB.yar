
rule Ransom_Linux_ECh0raix_C_MTB{
	meta:
		description = "Ransom:Linux/ECh0raix.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 10 3b 25 08 40 35 25 08 18 3b 25 08 48 35 25 08 20 3b 25 08 50 35 25 08 28 3b 25 08 58 35 25 08 30 3b 25 08 60 35 25 08 38 3b 25 08 68 35 25 08 40 3b 25 08 70 35 25 08 48 3b 25 08 78 35 25 08 50 3b 25 08 80 35 25 08 58 3b 25 08 88 35 25 08 60 3b 25 08 90 35 25 08 68 3b 25 08 98 35 25 } //01 00 
		$a_01_1 = {34 25 08 50 3a 25 08 80 34 25 08 58 3a 25 08 88 } //00 00 
	condition:
		any of ($a_*)
 
}