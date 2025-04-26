
rule Ransom_Win64_Filecoder_NITA_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6c 66 5f 64 65 6c 65 74 69 6e 67 5f 73 63 72 69 70 74 2e 76 62 73 } //2 self_deleting_script.vbs
		$a_01_1 = {42 6c 61 63 6b 53 74 72 69 6b 65 72 2e 70 64 62 } //2 BlackStriker.pdb
		$a_01_2 = {53 61 69 20 64 6f 20 6d 65 75 20 63 6f 64 69 67 6f } //1 Sai do meu codigo
		$a_01_3 = {4f 68 20 6e 6f } //1 Oh no
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}