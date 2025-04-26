
rule Trojan_BAT_AgentTesla_NEAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 6f 6c 64 65 6e 27 73 20 44 69 73 74 72 69 62 75 74 6f 72 73 20 32 30 32 31 } //5 Golden's Distributors 2021
		$a_01_1 = {67 65 74 5f 5f 31 35 31 5f 37 30 35 5f 30 33 33 5f 31 30 32 } //5 get__151_705_033_102
		$a_01_2 = {6e 75 6d 65 72 6f 44 65 43 6c 69 65 6e 74 } //2 numeroDeClient
		$a_01_3 = {53 61 75 76 65 67 61 72 64 65 72 46 69 63 68 69 65 72 } //2 SauvegarderFichier
		$a_01_4 = {53 47 41 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 SGA.Form1.resources
		$a_01_5 = {55 51 47 2e 64 } //2 UQG.d
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=18
 
}