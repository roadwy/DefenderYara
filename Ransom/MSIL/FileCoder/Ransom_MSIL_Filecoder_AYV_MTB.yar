
rule Ransom_MSIL_Filecoder_AYV_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 04 2b 17 09 11 04 9a 13 05 00 02 11 05 28 04 00 00 06 00 00 11 04 17 58 13 04 11 04 09 8e 69 32 e2 } //2
		$a_01_1 = {5c 55 73 65 72 73 5c 68 65 6c 6c 6f 5c 4f 6e 65 44 72 69 76 65 5c 42 75 72 65 61 75 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //1 \Users\hello\OneDrive\Bureau\Ransomware\Ransomware\obj\Debug\Ransomware.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}