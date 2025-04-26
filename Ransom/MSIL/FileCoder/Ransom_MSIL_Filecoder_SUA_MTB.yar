
rule Ransom_MSIL_Filecoder_SUA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 61 7a 65 6b 20 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //2 Bazek Ransomware.pdb
		$a_01_1 = {42 61 7a 65 6b 20 52 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //2 Bazek Ransomware.exe
		$a_01_2 = {42 61 7a 65 6b 47 72 6f 75 70 } //2 BazekGroup
		$a_01_3 = {45 6e 63 72 79 70 74 73 20 66 69 6c 65 73 20 61 6e 64 20 68 6f 6c 64 73 20 75 73 65 72 73 20 66 6f 72 20 72 61 6e 73 6f 6d } //1 Encrypts files and holds users for ransom
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}