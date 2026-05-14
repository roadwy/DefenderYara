
rule Trojan_Win64_Tedy_PGD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 79 76 65 72 6e 49 6e 6a 65 63 74 } //3 WyvernInject
		$a_01_1 = {43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 CryptGenRandom
		$a_01_2 = {43 65 72 74 46 72 65 65 43 65 72 74 69 66 69 63 61 74 65 43 6f 6e 74 65 78 74 } //1 CertFreeCertificateContext
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}