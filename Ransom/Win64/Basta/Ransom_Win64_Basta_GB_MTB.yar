
rule Ransom_Win64_Basta_GB_MTB{
	meta:
		description = "Ransom:Win64/Basta.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 81 90 00 00 00 b8 25 68 92 92 2b 83 8c 00 00 00 48 8b 0d 64 73 00 00 01 81 20 01 00 00 49 81 f9 a0 38 00 00 0f 8c c1 fe ff ff } //3
		$a_01_1 = {72 75 6e 64 6c 6c } //2 rundll
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}