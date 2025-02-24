
rule Ransom_Win64_Filecoder_SWJ_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.SWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 42 69 67 20 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //2 \x64\Release\Big Ransomware.pdb
		$a_01_1 = {5c 72 61 6e 73 6f 6d 5f 6e 6f 74 65 2e 74 78 74 } //2 \ransom_note.txt
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}