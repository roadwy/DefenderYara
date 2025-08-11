
rule Ransom_Win64_Filecoder_PAHD_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 d0 c1 e8 1e 31 d0 69 c0 65 89 07 6c 42 8d 14 20 42 89 14 a3 49 83 c4 01 49 81 fc 70 02 00 00 75 } //3
		$a_00_1 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All your files have been encrypted
		$a_00_2 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //2 Ransomware
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=6
 
}