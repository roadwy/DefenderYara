
rule Ransom_MSIL_Filecoder_PAFP_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 61 7a 65 6b 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Bazek Ransomware
		$a_01_1 = {45 6e 63 72 79 70 74 73 20 66 69 6c 65 73 20 61 6e 64 20 68 6f 6c 64 73 20 75 73 65 72 73 20 66 6f 72 20 72 61 6e 73 6f 6d } //1 Encrypts files and holds users for ransom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}