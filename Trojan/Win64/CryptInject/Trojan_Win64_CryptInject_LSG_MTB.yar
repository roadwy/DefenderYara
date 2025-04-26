
rule Trojan_Win64_CryptInject_LSG_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.LSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 12 48 8b 48 18 48 3b 51 10 } //1
		$a_01_1 = {4e 6f 20 68 6f 6f 6b 73 20 66 6f 75 6e 64 20 69 6e 20 74 68 69 73 20 6d 6f 64 75 6c 65 } //1 No hooks found in this module
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}