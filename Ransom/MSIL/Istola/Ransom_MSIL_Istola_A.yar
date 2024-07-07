
rule Ransom_MSIL_Istola_A{
	meta:
		description = "Ransom:MSIL/Istola.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 42 75 69 6c 64 65 72 31 } //2 RansomBuilder1
		$a_01_1 = {42 00 69 00 72 00 20 00 73 00 65 00 79 00 6c 00 65 00 72 00 69 00 20 00 79 00 61 00 6e 00 6c 00 69 00 73 00 20 00 79 00 61 00 70 00 69 00 79 00 6f 00 72 00 73 00 75 00 6e 00 } //2 Bir seyleri yanlis yapiyorsun
		$a_01_2 = {54 00 75 00 72 00 6b 00 48 00 61 00 63 00 6b 00 54 00 65 00 61 00 6d 00 2e 00 4f 00 72 00 67 00 } //2 TurkHackTeam.Org
		$a_01_3 = {52 61 6e 73 6f 6d 42 75 69 6c 64 65 72 31 2e 30 5c 52 61 6e 73 6f 6d 42 75 69 6c 64 65 72 31 2e 30 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 61 6e 73 6f 6d 42 75 69 6c 64 65 72 31 2e 30 2e 70 64 62 } //4 RansomBuilder1.0\RansomBuilder1.0\obj\Debug\RansomBuilder1.0.pdb
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4) >=8
 
}