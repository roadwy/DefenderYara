
rule Backdoor_Win64_Coroxy_A{
	meta:
		description = "Backdoor:Win64/Coroxy.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_02_0 = {fe c3 8a 94 2b 90 01 02 ff ff 02 c2 8a 8c 28 90 01 02 ff ff 88 8c 2b 90 01 02 ff ff 88 94 28 90 01 02 ff ff 02 ca 8a 8c 29 90 01 02 ff ff 30 0e 48 ff c6 48 ff cf 75 cd 90 00 } //5
		$a_00_1 = {2f 74 6f 72 2f 72 65 6e 64 65 7a 76 6f 75 73 32 2f 25 73 } //1 /tor/rendezvous2/%s
		$a_00_2 = {42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 } //1 BEGIN RSA PUBLIC KEY
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}