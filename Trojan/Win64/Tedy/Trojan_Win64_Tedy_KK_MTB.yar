
rule Trojan_Win64_Tedy_KK_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 32 f8 4d 8d 00 57 48 89 ff 48 8d 3f 5f 48 83 c2 01 4c 39 c2 75 e9 } //20
		$a_01_1 = {80 32 fc 4d 89 c9 48 89 ff 4d 89 c9 48 83 c2 01 4c 39 c2 75 eb } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Tedy_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b9 00 09 6e 88 f1 ff ff ff 48 8d 34 19 48 8d 76 ec 48 8b 7c 24 50 48 39 37 7d 93 } //20
		$a_01_1 = {48 8b 94 24 20 07 00 00 48 81 c2 38 02 00 00 4c 8b 84 24 d0 04 00 00 49 ff c8 48 8b 84 24 10 07 00 00 48 89 cb 48 8b b4 24 18 07 00 00 4c 89 c1 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Tedy_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 88 45 f7 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 00 88 45 f6 0f b6 45 f7 0a 45 f6 } //20
		$a_01_1 = {89 c2 0f b6 45 f7 22 45 f6 f7 d0 21 d0 88 45 f5 8b 45 f8 48 63 d0 48 8b 45 10 48 01 c2 0f b6 45 f5 88 02 83 45 fc 01 83 45 f8 01 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Tedy_KK_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 5d e0 48 89 5c 24 50 48 89 5c 24 48 48 89 5c 24 40 48 89 5c 24 38 89 5c 24 30 4c 89 74 24 28 4c 89 7c 24 20 4c 8b ce 45 33 c0 ba ff ff 1f 00 48 8d 4d e0 ff } //5
		$a_01_1 = {63 68 72 6f 6d 65 5f 64 65 63 72 79 70 74 5f 63 6f 6f 6b 69 65 73 2e 74 78 74 } //3 chrome_decrypt_cookies.txt
		$a_01_2 = {63 68 72 6f 6d 65 5f 64 65 63 72 79 70 74 5f 70 61 79 6d 65 6e 74 73 2e 74 78 74 } //2 chrome_decrypt_payments.txt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}