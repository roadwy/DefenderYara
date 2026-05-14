
rule Trojan_Win64_CryptoStealer_ARA_MTB{
	meta:
		description = "Trojan:Win64/CryptoStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 25 73 2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 } //2 ://api.telegram.org/bot%s/sendDocument
		$a_01_1 = {38 31 34 38 30 39 31 35 37 35 3a 41 41 45 47 30 43 6e 6a 75 48 4b 6f 68 6a 65 69 55 6f 35 32 73 4c 5a 65 36 41 43 61 79 4e 33 6b 56 47 45 } //2 8148091575:AAEG0CnjuHKohjeiUo52sLZe6ACayN3kVGE
		$a_80_2 = {57 61 6c 6c 65 74 73 } //Wallets  2
		$a_01_3 = {50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //2 Passwords.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}