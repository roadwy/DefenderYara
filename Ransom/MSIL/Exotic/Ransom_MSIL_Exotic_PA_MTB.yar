
rule Ransom_MSIL_Exotic_PA_MTB{
	meta:
		description = "Ransom:MSIL/Exotic.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 65 00 78 00 6f 00 74 00 69 00 63 00 } //1 .exotic
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 61 00 72 00 65 00 20 00 49 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 2c 00 20 00 62 00 79 00 20 00 74 00 68 00 65 00 20 00 45 00 58 00 4f 00 54 00 49 00 43 00 20 00 56 00 69 00 72 00 75 00 73 00 21 00 } //1 Windows are Infected, by the EXOTIC Virus!
		$a_01_2 = {6b 00 69 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 50 00 43 00 21 00 } //1 kill your PC!
		$a_01_3 = {66 00 75 00 63 00 6b 00 65 00 64 00 20 00 62 00 79 00 20 00 45 00 58 00 4f 00 54 00 49 00 43 00 20 00 53 00 51 00 55 00 41 00 44 00 21 00 } //1 fucked by EXOTIC SQUAD!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}