
rule Trojan_Win64_TigerCrypt_A_dha{
	meta:
		description = "Trojan:Win64/TigerCrypt.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 72 49 6e 74 65 72 66 61 63 65 40 40 } //150 CryptorInterface@@
		$a_01_1 = {43 72 79 70 74 6f 72 58 6f 72 40 40 } //50 CryptorXor@@
		$a_01_2 = {43 72 79 70 74 6f 72 44 45 53 40 40 } //50 CryptorDES@@
	condition:
		((#a_01_0  & 1)*150+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50) >=200
 
}