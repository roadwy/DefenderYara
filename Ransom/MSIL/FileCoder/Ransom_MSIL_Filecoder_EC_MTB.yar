
rule Ransom_MSIL_Filecoder_EC_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 } //1 Ransomware2.0
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Ransomware2._0.Properties.Resources
		$a_81_2 = {59 6f 75 72 20 6b 65 79 20 77 6f 72 6b 65 64 20 61 6c 6c 20 66 69 6c 65 73 20 61 72 65 20 6e 6f 77 20 64 65 63 72 79 70 74 65 64 20 21 } //1 Your key worked all files are now decrypted !
		$a_81_3 = {49 6e 63 6f 72 72 65 63 74 20 6b 65 79 20 6d 61 6b 65 20 73 75 72 65 20 79 6f 75 20 62 75 79 20 61 20 6b 65 79 } //1 Incorrect key make sure you buy a key
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}