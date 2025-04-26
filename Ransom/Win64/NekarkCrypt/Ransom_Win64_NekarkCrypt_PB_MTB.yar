
rule Ransom_Win64_NekarkCrypt_PB_MTB{
	meta:
		description = "Ransom:Win64/NekarkCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 46 69 6c 65 73 45 6e 63 72 79 70 74 65 64 2e 74 78 74 } //1 \FilesEncrypted.txt
		$a_01_1 = {59 6f 75 72 20 64 61 74 61 20 69 73 20 65 6e 63 72 79 70 74 65 64 } //1 Your data is encrypted
		$a_01_2 = {5c 4d 72 52 61 6e 6e 79 52 65 77 6f 72 6b 65 64 2e 70 64 62 } //3 \MrRannyReworked.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}