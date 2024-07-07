
rule Trojan_MacOS_NukeSped_C_MTB{
	meta:
		description = "Trojan:MacOS/NukeSped.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {75 6e 69 6f 6e 63 72 79 70 74 6f 2e 76 69 70 2f 75 70 64 61 74 65 } //2 unioncrypto.vip/update
		$a_00_1 = {4c 6f 61 64 65 72 2f 6d 61 63 6f 73 2f 42 61 72 62 65 71 75 65 2f } //1 Loader/macos/Barbeque/
		$a_00_2 = {31 32 47 57 41 50 43 54 31 46 30 49 31 53 31 34 } //3 12GWAPCT1F0I1S14
		$a_00_3 = {61 75 74 68 5f 74 69 6d 65 73 74 61 6d 70 } //1 auth_timestamp
		$a_00_4 = {61 75 74 68 5f 73 69 67 6e 61 74 75 72 65 } //1 auth_signature
		$a_02_5 = {48 8d 55 a8 e8 90 01 04 83 f8 01 0f 85 9b 00 00 00 48 8b 7d a8 48 8d 35 41 0f 00 00 ba 03 00 00 00 e8 90 01 04 48 85 c0 0f 84 a4 00 00 00 48 89 c6 b8 f5 ff ff ff 83 fb 02 0f 85 ec 00 00 00 4c 8d 75 a0 ba 04 00 00 00 b9 01 00 00 00 48 89 f7 4c 89 f6 e8 90 01 04 4d 8b 06 41 8b 40 10 90 00 } //1
		$a_02_6 = {be ff 01 00 00 48 89 df e8 90 01 04 e8 90 01 04 83 38 02 75 da 81 3b cf fa ed fe 75 d2 49 89 1e 31 c0 48 83 c4 08 5b 41 5c 41 5d 41 5e 41 5f 5d c3 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*3+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1) >=4
 
}