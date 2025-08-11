
rule Trojan_Win64_Tedy_KK_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 5d e0 48 89 5c 24 50 48 89 5c 24 48 48 89 5c 24 40 48 89 5c 24 38 89 5c 24 30 4c 89 74 24 28 4c 89 7c 24 20 4c 8b ce 45 33 c0 ba ff ff 1f 00 48 8d 4d e0 ff } //5
		$a_01_1 = {63 68 72 6f 6d 65 5f 64 65 63 72 79 70 74 5f 63 6f 6f 6b 69 65 73 2e 74 78 74 } //3 chrome_decrypt_cookies.txt
		$a_01_2 = {63 68 72 6f 6d 65 5f 64 65 63 72 79 70 74 5f 70 61 79 6d 65 6e 74 73 2e 74 78 74 } //2 chrome_decrypt_payments.txt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}