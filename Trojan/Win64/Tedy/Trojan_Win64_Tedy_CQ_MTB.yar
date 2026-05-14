
rule Trojan_Win64_Tedy_CQ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 c7 44 24 ?? ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 4c 8d 0d ?? ?? ?? ?? 48 8d 74 24 ?? 41 b8 ?? ?? ?? ?? 48 89 f1 ff d0 } //5
		$a_03_1 = {48 89 f8 48 03 05 ?? ?? ?? ?? 48 83 c4 ?? 5f 5e 48 ff e0 } //5
		$a_01_2 = {5b 2b 5d 20 68 65 6c 6c 6f 20 77 6f 6c 64 21 } //1 [+] hello wold!
		$a_01_3 = {63 72 79 70 74 } //1 crypt
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}