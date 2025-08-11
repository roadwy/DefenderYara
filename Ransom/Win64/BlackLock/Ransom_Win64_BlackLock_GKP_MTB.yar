
rule Ransom_Win64_BlackLock_GKP_MTB{
	meta:
		description = "Ransom:Win64/BlackLock.GKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 73 69 74 69 76 65 20 64 61 74 61 20 77 61 73 20 65 78 66 69 6c 74 72 61 74 65 64 20 61 6e 64 20 79 6f 75 72 20 73 79 73 74 65 6d 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 sensitive data was exfiltrated and your systems were encrypted
		$a_01_1 = {49 72 72 65 76 65 72 73 69 62 6c 65 20 6c 6f 73 73 20 6f 66 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 64 61 74 61 } //1 Irreversible loss of your encrypted data
		$a_01_2 = {77 65 20 68 61 76 65 20 73 74 6f 6c 65 6e 20 79 6f 75 72 20 64 61 74 61 } //1 we have stolen your data
		$a_01_3 = {2e 6f 6e 69 6f 6e 2f 63 68 61 74 } //1 .onion/chat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}