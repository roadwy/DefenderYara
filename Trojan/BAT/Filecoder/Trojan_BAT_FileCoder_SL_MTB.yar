
rule Trojan_BAT_FileCoder_SL_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {4b 61 64 61 76 72 6f 56 65 63 74 6f 72 } //1 KadavroVector
		$a_81_1 = {4b 61 64 61 76 72 6f 56 65 63 74 6f 72 52 61 6e 73 6f 6d 77 61 72 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 KadavroVectorRansomware.My.Resources
		$a_81_2 = {24 35 30 63 34 39 64 65 39 2d 39 31 34 61 2d 34 32 65 38 2d 61 39 66 36 2d 32 38 35 66 37 63 61 38 63 37 31 65 } //1 $50c49de9-914a-42e8-a9f6-285f7ca8c71e
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}