
rule Trojan_Win64_CryptInject_BE_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6b c2 7c b9 17 00 00 00 c1 e2 05 8b c2 41 83 e8 2c 4c 0f af c0 49 8b c2 49 f7 e0 48 c1 ea 07 48 69 c2 ff 00 00 00 4c 2b c0 41 0f b6 c0 0f 45 c8 33 d2 41 88 0c 39 ff c2 81 fa f0 49 02 00 } //2
		$a_01_1 = {73 76 6f 67 66 69 69 66 6f 74 75 7a } //2 svogfiifotuz
		$a_01_2 = {7a 73 61 64 73 67 6a 65 61 } //2 zsadsgjea
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}