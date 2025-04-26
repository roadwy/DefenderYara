
rule Ransom_MSIL_HaoCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/HaoCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 68 00 61 00 6f 00 31 00 37 00 } //1 .hao17
		$a_01_1 = {5c 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 2e 00 6a 00 70 00 67 00 } //1 \ransom.jpg
		$a_01_2 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 \Desktop\README.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}