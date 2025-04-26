
rule Trojan_Win64_CryptInject_NR_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 6c 65 73 73 50 45 4c 6f 61 64 65 72 2e 70 64 62 } //1 FilelessPELoader.pdb
		$a_01_1 = {46 61 69 6c 65 64 20 69 6e 20 72 65 74 72 69 65 76 69 6e 67 20 74 68 65 20 53 68 65 6c 6c 63 6f 64 65 } //1 Failed in retrieving the Shellcode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}