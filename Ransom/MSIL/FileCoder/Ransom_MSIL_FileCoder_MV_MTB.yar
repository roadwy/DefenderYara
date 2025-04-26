
rule Ransom_MSIL_FileCoder_MV_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //1 vssadmin delete shadows /all
		$a_81_1 = {45 6e 63 44 6c 6c 2e 70 64 62 } //1 EncDll.pdb
		$a_81_2 = {62 74 63 20 74 6f 20 6d 79 20 61 64 64 72 65 73 73 } //1 btc to my address
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}