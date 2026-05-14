
rule Ransom_MSIL_Zusy_MK_MTB{
	meta:
		description = "Ransom:MSIL/Zusy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 45 41 44 4d 45 5f 4e 42 4c 4f 43 4b 2e 74 78 74 } //5 README_NBLOCK.txt
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 6c 6f 63 6b 65 64 20 77 69 74 68 20 41 45 53 2d 32 35 36 2e } //3 All your files are locked with AES-256.
		$a_81_2 = {6b 65 79 2e 62 69 6e 20 2d 20 49 74 20 69 73 20 79 6f 75 72 20 6f 6e 6c 79 20 72 65 63 6f 76 65 72 79 20 74 6f 6f 6c 2e } //2 key.bin - It is your only recovery tool.
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*3+(#a_81_2  & 1)*2) >=10
 
}