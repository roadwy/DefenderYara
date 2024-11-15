
rule Ransom_MSIL_Filecoder_SWA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 4f 53 55 2e 70 64 62 } //2 NOSU.pdb
		$a_01_1 = {4e 4f 53 55 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 NOSU.Resources.resources
		$a_01_2 = {54 00 68 00 65 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 77 00 61 00 73 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 74 00 68 00 65 00 20 00 4e 00 4f 00 53 00 55 00 20 00 76 00 69 00 72 00 75 00 73 00 } //1 The system was infected with the NOSU virus
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 } //1 DisableAntiSpyware
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}