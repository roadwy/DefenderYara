
rule Trojan_Win64_DGCrypt_MCQ_MTB{
	meta:
		description = "Trojan:Win64/DGCrypt.MCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 61 6d 62 64 61 5f 35 31 33 38 37 62 63 62 64 39 38 37 66 30 32 37 37 39 63 31 64 31 35 31 39 61 32 33 31 36 34 37 } //1 lambda_51387bcbd987f02779c1d1519a231647
		$a_01_1 = {6c 61 6d 62 64 61 5f 39 64 31 64 32 39 34 32 39 62 38 39 34 31 65 65 63 31 65 36 34 39 31 37 33 39 38 64 65 34 36 35 } //1 lambda_9d1d29429b8941eec1e64917398de465
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}