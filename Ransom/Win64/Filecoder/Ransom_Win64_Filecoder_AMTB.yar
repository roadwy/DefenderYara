
rule Ransom_Win64_Filecoder_AMTB{
	meta:
		description = "Ransom:Win64/Filecoder!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 55 73 65 72 73 5c 68 75 73 74 6c 65 72 5c 44 6f 63 75 6d 65 6e 74 73 48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 } //C:\Users\hustler\DocumentsHello, world!  2
		$a_80_1 = {63 72 79 70 74 65 6e 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //cryptencrypted successfully  1
		$a_80_2 = {6d 6f 6e 65 79 6c 6f 63 6b 65 72 2e 70 64 62 } //moneylocker.pdb  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2) >=4
 
}