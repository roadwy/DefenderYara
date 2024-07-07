
rule Ransom_MSIL_Kekw_AA_MTB{
	meta:
		description = "Ransom:MSIL/Kekw.AA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 45 4b 57 2e 65 78 65 } //2 KEKW.exe
		$a_01_1 = {72 65 70 6f 73 5c 4b 45 4b 57 5c 6f 62 6a 5c 44 65 62 75 67 5c 4b 45 4b 57 2e 70 64 62 } //1 repos\KEKW\obj\Debug\KEKW.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}