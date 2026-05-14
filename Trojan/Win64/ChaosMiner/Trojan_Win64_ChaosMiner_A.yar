
rule Trojan_Win64_ChaosMiner_A{
	meta:
		description = "Trojan:Win64/ChaosMiner.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 6f 6c 61 6e 67 2d 63 72 79 70 74 6f 6d 69 6e 65 72 2f 4e 65 74 77 6f 72 6b 2f 43 6c 69 65 6e 74 } //1 golang-cryptominer/Network/Client
		$a_01_1 = {68 74 74 70 2e 73 6f 63 6b 73 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 } //1 http.socksUsernamePassword
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}