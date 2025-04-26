
rule Ransom_MSIL_PubG_DA_MTB{
	meta:
		description = "Ransom:MSIL/PubG.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 46 69 6c 65 73 20 61 72 65 20 61 6c 6c 20 44 65 63 72 79 70 74 65 64 } //5 Your Files are all Decrypted
		$a_81_1 = {2e 70 75 62 67 } //5 .pubg
		$a_81_2 = {45 6e 63 72 79 70 74 65 64 } //5 Encrypted
		$a_81_3 = {47 42 55 50 52 61 6e 73 6f 6d 77 61 72 65 } //1 GBUPRansomware
		$a_81_4 = {50 55 42 47 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 PUBG Ransomware
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=16
 
}