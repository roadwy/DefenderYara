
rule Ransom_Win64_Pydomer_A{
	meta:
		description = "Ransom:Win64/Pydomer.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {78 da b5 7a 4d 6c 23 49 96 5e 66 f2 57 94 4a a5 aa ae 96 aa aa ff d4 3d dd 35 ad 9e ee 2a 8a 92 6a 4a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}