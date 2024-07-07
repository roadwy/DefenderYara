
rule Ransom_MSIL_JigsawCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/JigsawCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 00 53 00 61 00 68 00 65 00 72 00 20 00 42 00 6c 00 75 00 65 00 20 00 45 00 61 00 67 00 6c 00 65 00 } //1 .Saher Blue Eagle
		$a_01_1 = {6a 00 69 00 67 00 73 00 61 00 77 00 2d 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //1 jigsaw-ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}