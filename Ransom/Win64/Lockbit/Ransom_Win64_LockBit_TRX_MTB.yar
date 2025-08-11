
rule Ransom_Win64_LockBit_TRX_MTB{
	meta:
		description = "Ransom:Win64/LockBit.TRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 6d 79 20 64 61 74 61 2e 74 78 74 } //1 How to decrypt my data.txt
		$a_01_1 = {59 6f 75 72 20 64 65 63 72 79 70 74 20 49 44 3a } //1 Your decrypt ID:
		$a_01_2 = {40 70 72 6f 74 6f 6e 2e 6d 65 } //1 @proton.me
		$a_01_3 = {61 69 5c 61 6b 34 37 5c 77 72 69 74 65 6e 75 6c 6c 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 77 72 69 74 65 6e 75 6c 6c 2e 70 64 62 } //2 ai\ak47\writenull\x64\Release\writenull.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}