
rule Ransom_MSIL_Crimas_A{
	meta:
		description = "Ransom:MSIL/Crimas.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 4d 61 73 74 65 72 } //1 CryptoMaster
		$a_01_1 = {48 00 4f 00 57 00 20 00 54 00 4f 00 20 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 20 00 46 00 49 00 4c 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //1 HOW TO DECRYPT FILES.txt
		$a_01_2 = {2f 00 70 00 73 00 2e 00 63 00 65 00 } //1 /ps.ce
		$a_01_3 = {2f 00 74 00 78 00 2e 00 63 00 65 00 } //1 /tx.ce
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}